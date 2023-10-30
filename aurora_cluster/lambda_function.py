import boto3
import botocore
from botocore.exceptions import ClientError

import re
import json
import os
import subprocess
import tempfile
import traceback
import zipfile
import hashlib

from extutil import remove_none_attributes, account_context, ExtensionHandler, ext, \
    current_epoch_time_usec_num, component_safe_name, create_zip, \
    handle_common_errors, random_id, lambda_env


eh = ExtensionHandler()

DELETED_STATUS = "gone"

rds = boto3.client("rds")
def lambda_handler(event, context):\
    # 1. Zero
    # 3. Full
    try:
        print(f"event = {event}")
        account_number = account_context(context)['number']
        region = account_context(context)['region']
        eh.capture_event(event)
        prev_state = event.get("prev_state") or {}
        cdef = event.get("component_def")
        cname = event.get("component_name")
        project_code = event.get("project_code")
        repo_id = event.get("repo_id")
        
        name = cdef.get("name") or component_safe_name(project_code, repo_id, cname, no_underscores=True, max_chars=63)
        
        # availability_zones = cdef.get("availability_zones") or event.get("aws_info", {}).get("region_availability_zones") or ["us-east-1a", "us-east-1b", "us-east-1c"]
        backup_retention_period = cdef.get("backup_retention_period") or 7
        character_set_name = cdef.get("character_set_name") #We do not recommend you set this parameter
        
        security_group_ids = cdef.get("security_group_ids")
        subnet_ids = cdef.get("subnet_ids")
        if not security_group_ids or (not subnet_ids):
            eh.perm_error("Must specify security_group_ids and subnet_ids", 0)
            eh.add_log("Error, security_group_ids and subnet_ids Required", {"definition": cdef}, True)
            return eh.finish()

        engine = cdef.get("engine") or "aurora-postgresql"
        if engine not in ["aurora-mysql", "aurora-postgresql"]:
            eh.perm_error("Invalid Engine", 0)
            eh.add_log("Error, Invalid Engine", {"engine": engine}, True)
            return eh.finish()

        database_name = cdef.get("database_name") or get_default_database_name(engine)

        engine_version = cdef.get("engine_version")
        if engine_version and not eh.state.get("engine_version"):
            eh.add_state({"engine_version": engine_version})

        parameter_group_name = cdef.get("parameter_group_name")
        # if parameter_group_name and not eh.state.get("parameter_group_name"):
        #     eh.add_state({"parameter_group_name": parameter_group_name})

        port = cdef.get("port") or get_default_port(engine)
        master_username = cdef.get("master_username") or "administrator"
        master_password = cdef.get("master_password")
        manage_master_user_password = cdef.get("manage_master_user_password") or False
        master_user_secret_kms_key_id = cdef.get("master_user_secret_kms_key_id")
        if not master_password and (not manage_master_user_password):
            eh.perm_error("Must specify master_password", 0)
            eh.add_log("Error, master_password Required", {"definition": cdef}, True)
            return eh.finish()

        # option_group_name = cdef.get("option_group_name")
        preferred_backup_window = cdef.get("preferred_backup_window") or "05:12-05:42"
        preferred_maintenance_window = cdef.get("preferred_maintenance_window") or "mon:06:09-mon:06:39"

        replicate_source_arn = cdef.get("replicate_source_arn")
        tags = cdef.get("tags") or {}
        storage_encrypted = cdef.get("storage_encrypted", True)

        kms_key_id = cdef.get("kms_key_id")
        pre_signed_url = cdef.get("pre_signed_url")
        enable_iam_authentication = cdef.get("enable_iam_authentication", False)
        backtrack_window = cdef.get("backtrack_window", 0) if engine == "aurora-mysql" else None
        enable_cloudwatch_logs_exports = cdef.get("enable_cloudwatch_logs_exports", get_default_logs_exports(engine))
        
        engine_mode = cdef.get("engine_mode", "provisioned")
        scaling_configuration = cdef.get("scaling_configuration")
        
        deletion_protection = cdef.get("deletion_protection", False)
        global_cluster_identifier = cdef.get("global_cluster_identifier")
        copy_tags_to_snapshot = cdef.get("copy_tags_to_snapshot", False)

        activty_directory_id = cdef.get("activty_directory_id")
        activty_directory_role_name = cdef.get("activty_directory_role_name")

        enable_global_write_forwarding = cdef.get("enable_global_write_forwarding", False if global_cluster_identifier else None)
        force_master_password_update = cdef.get("force_update", False)
        skip_final_snapshot = cdef.get("skip_final_snapshot", False)

        storage_type = cdef.get("storage_type", "aurora")
        if storage_type not in ["aurora", "aurora-iopt1"]:
            eh.perm_error("Invalid Storage Type", 0)
            eh.add_log("Error, Invalid Storage Type", {"storage_type": storage_type}, True)
            return eh.finish()

        # enable_local_write_forwarding = cdef.get("enable_local_write_forwarding", False)

        apply_changes_immediately = cdef.get("apply_changes_immediately", False)

        pass_back_data = event.get("pass_back_data", {})
        if pass_back_data:
            pass

        elif event.get("op") == "upsert":
            eh.add_op("get_subnets")
            eh.add_op("get_subnet_group")
            if not eh.state.get("engine_version"):
                eh.add_op("get_engine_version")
            eh.add_op("get_cluster")

        elif event.get("op") == "delete":
            eh.add_op("delete_cluster")
        
        initial_attributes = remove_none_attributes({
            "BackupRetentionPeriod": backup_retention_period,
            "CharacterSetName": character_set_name,
            "DatabaseName": database_name,
            "DBClusterIdentifier": name,
            "DBClusterParameterGroupName": parameter_group_name, #This should be managed separately
            "VpcSecurityGroupIds": security_group_ids,
            "Engine": engine,
            "Port": port,
            "MasterUsername": master_username,
            "MasterUserPassword": master_password,
            # "OptionGroupName": option_group_name,
            "PreferredBackupWindow": preferred_backup_window,
            "PreferredMaintenanceWindow": preferred_maintenance_window,
            "ReplicationSourceIdentifier": replicate_source_arn,
            "Tags": format_tags(tags),
            "StorageEncrypted": storage_encrypted,
            "KmsKeyId": kms_key_id,
            "PreSignedUrl": pre_signed_url,
            "EnableIAMDatabaseAuthentication": enable_iam_authentication,
            "BacktrackWindow": backtrack_window,
            "EnableCloudwatchLogsExports": enable_cloudwatch_logs_exports,
            "EngineMode": engine_mode,
            "ScalingConfiguration": scaling_configuration,
            "DeletionProtection": deletion_protection,
            "GlobalClusterIdentifier": global_cluster_identifier,
            "CopyTagsToSnapshot": copy_tags_to_snapshot,
            "Domain": activty_directory_id,
            "DomainIAMRoleName": activty_directory_role_name,
            "EnableGlobalWriteForwarding": enable_global_write_forwarding,
            "StorageType": storage_type,
            "ManageMasterUserPassword": manage_master_user_password,
            "MasterUserSecretKmsKeyId": master_user_secret_kms_key_id,
            # "EnableLocalWriteForwarding": enable_local_write_forwarding
        })

        get_subnet_group(subnet_ids)
        create_subnet_group(name)
        initial_attributes["DBSubnetGroupName"] = eh.props.get("subnet_group_name")
        initial_attributes["AvailabilityZones"] = eh.props.get("availability_zones")

        # Note that updating the engine version will cause an outage.
        # Each deployment will auto-update the engine version during the downtime window
        get_engine_version(engine)
        initial_attributes["EngineVersion"] = eh.state.get("engine_version")


        # attributes = {k:str(v) for k,v in attributes.items() if not isinstance(v, dict)}
        # print(initial_attributes)
        

        get_cluster(prev_state, initial_attributes, region, force_master_password_update)
        create_cluster(initial_attributes, region)
        update_cluster(prev_state, initial_attributes, region, apply_changes_immediately)
        delete_cluster(prev_state, skip_final_snapshot)
        waiting_for_cluster()

        add_tags()
        remove_tags()
            
        return eh.finish()

    except Exception as e:
        msg = traceback.format_exc()
        print(msg)
        eh.add_log("Unexpected Error", {"error": msg}, is_error=True)
        eh.declare_return(200, 0, error_code=str(e))
        return eh.finish()

@ext(handler=eh, op="get_subnet_group")
def get_subnet_group(subnet_ids):
    try:
        first = True
        marker = None
        while first or marker:
            first = False
            params = remove_none_attributes({
                "Marker": marker
            })
            subnet_group_retval = rds.describe_db_subnet_groups(**params)
            marker = subnet_group_retval.get("Marker")
            subnet_groups = subnet_group_retval.get("DBSubnetGroups")
            for subnet_group in subnet_groups:
                group_subnet_ids = [subnet.get("SubnetIdentifier") for subnet in subnet_group.get("Subnets")]
                if set(group_subnet_ids) == set(subnet_ids):
                    eh.add_log("Found Matching Subnet Group", subnet_group)
                    eh.add_props({
                        "subnet_group_arn": subnet_group.get("DBSubnetGroupArn"),
                        "subnet_group_name": subnet_group.get("DBSubnetGroupName"),
                        "availability_zones": [subnet.get("SubnetAvailabilityZone").get("Name") for subnet in subnet_group.get("Subnets")]
                    })
                    return None
        
        # If we get here, we need to create a new subnet group
        eh.add_op("create_subnet_group", {"subnet_ids": subnet_ids})
    except ClientError as e:
        handle_common_errors(e, eh, "Get Subnet Group Failed", 0)

@ext(handler=eh, op="create_subnet_group")
def create_subnet_group(name):
    subnet_ids = eh.ops["create_subnet_group"]["subnet_ids"]

    # Get a hash of the subnet ids
    dhash = hashlib.md5()
    dhash.update(json.dumps(subnet_ids, sort_keys=True).encode())
    subnet_group_name = f"ck-subnet-group-{dhash.hexdigest()}"

    try:
        subnet_group_retval = rds.create_db_subnet_group(
            DBSubnetGroupName=subnet_group_name,
            DBSubnetGroupDescription=f"Subnet Group Created for Cluster {name}",
            SubnetIds=subnet_ids,
            Tags=[
                {
                    "Key": "CreatedBy",
                    "Value": "CloudKommand"
                }
            ]
        ).get("DBSubnetGroup")
        eh.add_props({
            "subnet_group_arn": subnet_group_retval.get("DBSubnetGroupArn"),
            "subnet_group_name": subnet_group_retval.get("DBSubnetGroupName"),
            "availability_zones": [subnet.get("SubnetAvailabilityZone").get("Name") for subnet in subnet_group_retval.get("Subnets")]
        })
        eh.add_log("Created Subnet Group", subnet_group_retval)
    except ClientError as e:
        handle_common_errors(e, eh, "Create Subnet Group Failed", 0)


@ext(handler=eh, op="get_engine_version")
def get_engine_version(engine):
    try:
        engine_version_retval = rds.describe_db_engine_versions(
            Engine=engine
        )
        print(engine_version_retval)
        import re


        #Get the latest version of this engine
        max_version_number = max([float(re.sub(r'[^0-9.]', '', version.get("EngineVersion"))) for version in engine_version_retval.get("DBEngineVersions")])
        version_to_use = list([version for version in engine_version_retval.get("DBEngineVersions") if float(re.sub(r'[^0-9.]', '', version.get("EngineVersion"))) == max_version_number])[0].get("EngineVersion")
        eh.add_log("Selected Engine Version", {"All Versions": engine_version_retval, "Used Version": version_to_use})

        eh.add_state({
            "engine_version": version_to_use
        })
    except ClientError as e:
        handle_common_errors(e, eh, "Get Engine Versions Failed", 0)

@ext(handler=eh, op="get_cluster")
def get_cluster(prev_state, attributes, region, force_master_password_update):
    try:
        dhash = hashlib.md5()
        hash_attributes = {k:v for k,v in attributes.items() if k not in ["Tags"]}
        dhash.update(json.dumps(hash_attributes, sort_keys=True).encode())
        eh.add_props({"attributes_hash": dhash.hexdigest()})

        identifier_to_find = prev_state.get("props", {}).get("name") or attributes["DBClusterIdentifier"]
        cluster_retval = rds.describe_db_clusters(
            DBClusterIdentifier=identifier_to_find
        ).get("DBClusters")[0]

        eh.add_log("Got Cluster", cluster_retval)
        
        # Check vs old hash. This auto-detects most changes
        if prev_state.get("props", {}).get("attributes_hash") != eh.props.get("attributes_hash"):
            print(prev_state.get('props', {}).get('attributes_hash'))
            print(eh.props.get('attributes_hash'))
            eh.add_op("update_cluster")

        # Check whether we need to update tags
        current_tags_dict = {tag.get("Key"): tag.get("Value") for tag in cluster_retval.get("TagList")}
        desired_tags_dict = {tag.get("Key"): tag.get("Value") for tag in attributes.get("Tags")}
        if current_tags_dict != desired_tags_dict:
            eh.add_log("Tags Don't Match", {"current_tags": current_tags_dict, "desired_tags": desired_tags_dict})
            update_tags = {k:v for k,v in desired_tags_dict.items() if ((k not in current_tags_dict) or (v != current_tags_dict.get(k)))}
            remove_tags = [k for k in current_tags_dict if k not in desired_tags_dict]
            if update_tags:
                eh.add_op("add_tags", update_tags)
            if remove_tags:
                eh.add_op("remove_tags", remove_tags)

        if not eh.ops.get("update_cluster"):
            for attrib_key, attrib_value in attributes.items():
                if attrib_key == "MasterUserPassword":
                    if force_master_password_update:
                        eh.add_op("update_cluster")
                    
                elif attrib_key in ["StorageType", "Tags"]:
                    continue #These are ignored

                elif attrib_key == "VpcSecurityGroupIds":
                    if set(attrib_value) != set(map(lambda x: x["VpcSecurityGroupId"], cluster_retval.get("VpcSecurityGroups"))):
                        print("VPC Security Groups Don't Match")
                        eh.add_op("update_cluster")
                
                elif attrib_key == "DBSubnetGroupName":
                    if attrib_value != cluster_retval.get("DBSubnetGroup"):
                        print("Subnet Groups Don't Match")
                        eh.add_op("update_cluster")
                
                elif attrib_key == "EnableCloudwatchLogsExports":
                    if set(attrib_value) != set(cluster_retval.get("EnabledCloudwatchLogsExports")):
                        print("Cloudwatch Logs Exports Don't Match")
                        eh.add_op("update_cluster")

                elif attrib_key == "ManageMasterUserPassword":
                    if bool(attrib_value) != bool(cluster_retval.get("MasterUserSecret")):
                        print("ManageMasterUserPassword Doesn't Match")
                        eh.add_op("update_cluster")

                elif attrib_key == "EnableIAMDatabaseAuthentication":
                    if attrib_value != cluster_retval.get("IAMDatabaseAuthenticationEnabled"):
                        print("EnableIAMDatabaseAuthentication Doesn't Match")
                        eh.add_op("update_cluster")

                elif attrib_value != cluster_retval.get(attrib_key):
                    if isinstance(attrib_value, list):
                        if set(attrib_value) != set(cluster_retval.get(attrib_key, [])):
                            print(f"attrib_key = {attrib_key}, attrib_value = {attrib_value}, cluster_retval.get(attrib_key) = {cluster_retval.get(attrib_key)}")
                            eh.add_op("update_cluster")
                    elif attrib_key in ["Engine", "MasterUsername"]:
                        eh.add_log(f"Cannot Change Subnets or Engine", {"attributes": attributes, "cluster_retval": cluster_retval})
                        eh.perm_error(f"Cannot Change Subnets or Engine", 2)
                        return None
                    else:
                        print(f"attrib_key = {attrib_key}, attrib_value = {attrib_value}, cluster_retval.get(attrib_key) = {cluster_retval.get(attrib_key)}")
                        eh.add_op("update_cluster")
                        continue

        attributes_to_log = {k:v for k,v in attributes.items() if k not in ["VpcSecurityGroupIds", "MasterUserPassword"]}
        if not eh.ops.get("update_cluster"):
            eh.add_log("Cluster Attributes Match", {"attributes": attributes_to_log, "cluster_retval": cluster_retval})
            update_props_and_links(eh, region, cluster_retval)
        else:
            eh.add_log("Cluster Attributes Don't Match", {"attributes": attributes_to_log, "cluster_retval": cluster_retval})


    except ClientError as e:
        if e.response['Error']['Code'] in ["DBClusterNotFoundFault"]:
            eh.add_log("Cluster Not Found", {"name": attributes["DBClusterIdentifier"]})
            eh.add_op("create_cluster")
        else:
            handle_common_errors(e, eh, "Get Cluster Failed", 0)


@ext(handler=eh, op="create_cluster")
def create_cluster(attributes, region):
    try:
        cluster_retval = rds.create_db_cluster(
            **attributes
        ).get("DBCluster")

        eh.add_log("Created Cluster", cluster_retval)
        
        update_props_and_links(eh, region, cluster_retval)
        eh.add_op("waiting_for_cluster", {"cluster_id": cluster_retval.get("DBClusterIdentifier"), "desired_status": "available"})

    except ClientError as e:
        handle_common_errors(e, eh, "Create Cluster Failed", 15, ["InvalidParameterCombination", "InvalidParameterValue"])
    except botocore.exceptions.ParamValidationError as e:
        eh.add_log("Invalid Create Cluster Parameters", {"error": str(e), "attributes": attributes}, True)
        eh.perm_error(str(e), 15)

@ext(handler=eh, op="update_cluster")
def update_cluster(prev_state, attributes, region, apply_immediately):
    try:
        old_name = prev_state.get("props", {}).get("name")
        if old_name and old_name != attributes["DBClusterIdentifier"]:
            attributes["NewDBClusterIdentifier"] = attributes["DBClusterIdentifier"]
            attributes["DBClusterIdentifier"] = old_name

        if apply_immediately:
            attributes["ApplyImmediately"] = True

        cluster_retval = rds.modify_db_cluster(
            **{k:v for k,v in attributes.items() if k in [
                "DBClusterIdentifier", "NewDBClusterIdentifier", "ApplyImmediately", "BackupRetentionPeriod", "DBClusterParameterGroupName", "VpcSecurityGroupIds", 
                "Port", "MasterUserPassword", "OptionGroupName", "PreferredBackupWindow", "PreferredMaintenanceWindow", "EnableIAMDatabaseAuthentication", "BacktrackWindow", 
                "CloudwatchLogsExportConfiguration", "EngineVersion", "AllowMajorVersionUpgrade", "DBInstanceParameterGroupName", "Domain", "DomainIAMRoleName", "ScalingConfiguration", 
                "DeletionProtection", "EnableHttpEndpoint", "CopyTagsToSnapshot", "EnableGlobalWriteForwarding", "DBClusterInstanceClass", "AllocatedStorage", "StorageType", "Iops", 
                "AutoMinorVersionUpgrade", "MonitoringInterval", "MonitoringRoleArn", "EnablePerformanceInsights", "PerformanceInsightsKMSKeyId", "PerformanceInsightsRetentionPeriod", 
                "ServerlessV2ScalingConfiguration", "NetworkType", "ManageMasterUserPassword", "RotateMasterUserPassword", "MasterUserSecretKmsKeyId", "AllowEngineModeChange", 
                "EnableLocalWriteForwarding", "AwsBackupRecoveryPointArn"]
            }
        ).get("DBCluster")

        eh.add_log("Updated Cluster", cluster_retval)

        update_props_and_links(eh, region, cluster_retval)
        eh.add_op("waiting_for_cluster", {"cluster_id": cluster_retval.get("DBClusterIdentifier"), "desired_status": "available"})

    except ClientError as e:
        handle_common_errors(e, eh, "Update Cluster Failed", 15, ["InvalidDBClusterStateFault"])
    except botocore.exceptions.ParamValidationError as e:
        eh.add_log("Invalid Update Cluster Parameters", {"error": str(e), "attributes": attributes}, True)
        eh.perm_error(str(e), 15)

@ext(handler=eh, op="delete_cluster")
def delete_cluster(prev_state, skip_final_snapshot):
    try:
        params = remove_none_attributes({
            "DBClusterIdentifier": prev_state.get("props", {}).get("name"),
            "SkipFinalSnapshot": skip_final_snapshot,
            "FinalDBSnapshotIdentifier": f"{prev_state.get('props', {}).get('name')}-final-snapshot" if not skip_final_snapshot else None
        })

        cluster_retval = rds.delete_db_cluster(**params).get("DBCluster")

        eh.add_log("Deleted Cluster", cluster_retval)
        eh.add_op("waiting_for_cluster", {"cluster_id": prev_state.get("props", {}).get("name"), "desired_status": DELETED_STATUS})
    except ClientError as e:
        if e.response['Error']['Code'] in ["DBClusterNotFoundFault"]:
            eh.add_log("Cluster Not Found, Exiting", {"name": prev_state.get("props", {}).get("name")})
        else:
            handle_common_errors(e, eh, "Delete Cluster Failed", 15, ["InvalidParameterCombination"])

@ext(handler=eh, op="waiting_for_cluster")
def waiting_for_cluster():
    cluster_id = eh.ops["waiting_for_cluster"]["cluster_id"]
    desired_status = eh.ops["waiting_for_cluster"]["desired_status"]
    try:
        cluster_retval = rds.describe_db_clusters(
            DBClusterIdentifier=cluster_id
        ).get("DBClusters")[0]
        current_status = cluster_retval.get("Status")
        if current_status == desired_status:
            eh.add_log(f"Cluster Update Finished, Status: {desired_status}", {"cluster_retval": cluster_retval})
        else:
            eh.add_log(f"Waiting for Cluster Status: {desired_status}", {"desired_status": desired_status, "current_status": current_status})
            eh.retry_error(str(current_epoch_time_usec_num), 60, callback_sec=10)
    except ClientError as e:
        if desired_status == DELETED_STATUS and e.response['Error']['Code'] in ["DBClusterNotFoundFault"]:
            eh.add_log("Cluster Deleted", {"name": cluster_id})
            return None

@ext(handler=eh, op="add_tags")
def add_tags():
    tags_to_add = format_tags(eh.ops["add_tags"])
    try:
        rds.add_tags_to_resource(
            ResourceName=eh.props.get("arn"),
            Tags=tags_to_add
        )
        eh.add_log("Added Tags", {"tags": tags_to_add})
    except ClientError as e:
        handle_common_errors(e, eh, "Add Tags Failed", 90)

@ext(handler=eh, op="remove_tags")
def remove_tags():
    tags_to_remove = eh.ops["remove_tags"]
    try:
        rds.remove_tags_from_resource(
            ResourceName=eh.props.get("arn"),
            TagKeys=tags_to_remove
        )
        eh.add_log("Removed Tags", {"tags": tags_to_remove})
    except ClientError as e:
        handle_common_errors(e, eh, "Remove Tags Failed", 94)



# @ext(handler=eh, op="get_parameter_group")
# def get_parameter_group(engine):
#     try:
#         engine_version_retval = rds.describe_db_engine_versions(
#             Engine=engine, EngineVersion=eh.state.get("engine_version")
#         )

#         #Get the set of allowed parameter group families
#         allowed_families = list(set([version.get("DBParameterGroupFamily") for version in engine_version_retval.get("DBEngineVersions")]))
#         allowed_families.sort(reverse=True)

#         eh.add_state({
#             "parameter_group_family": allowed_families[0]
#         })

#         parameter_group_retval = rds.describe_db_parameter_groups(

        



@ext(handler=eh, op="compare_defs")
def compare_defs(event):
    old_digest = event.get("prev_state", {}).get("props", {}).get("def_hash")
    new_rendef = event.get("component_def")

    _ = new_rendef.pop("trust_level", None)

    dhash = hashlib.md5()
    dhash.update(json.dumps(new_rendef, sort_keys=True).encode())
    digest = dhash.hexdigest()
    eh.add_props({"def_hash": digest})

    if old_digest == digest:
        eh.add_log("Definitions Match, Checking Deploy Code", {"old_hash": old_digest, "new_hash": digest})
        eh.add_op("check_code_sha") 

    else:
        eh.add_log("Definitions Don't Match, Deploying", {"old": old_digest, "new": digest})


def update_props_and_links(eh, region, output):
    eh.add_props({
        "engine": output.get("Engine"),
        "name": output.get("DBClusterIdentifier"),
        "arn": output.get("DBClusterArn"),
        "id": output.get("DbClusterResourceId"),
        "endpoint": output.get("Endpoint"),
        "reader_endpoint": output.get("ReaderEndpoint"),
        "system_id": output.get("DBSystemId"),
        "clone_group_id": output.get("CloneGroupId"),
    })

    if output.get("MasterUserSecret"):
        eh.add_props({
            "secret_arn": output.get("MasterUserSecret").get("SecretArn")    
        })
    
    eh.add_links({
        "Cluster": gen_cluster_link(region, output.get("DBClusterIdentifier"))
    })

def gen_cluster_link(region, name):
    return f"https://{region}.console.aws.amazon.com/rds/home?region={region}#database:id={name};is-cluster=true"

def get_default_port(engine):
    if engine == "aurora-mysql":
        return 3306
    elif engine == "aurora-postgresql":
        return 5432
    else:
        raise Exception(f"Invalid Engine: {engine}")

def get_default_logs_exports(engine):
    if engine == "aurora-mysql":
        return ["audit", "error", "general", "slowquery"]
    elif engine == "aurora-postgresql":
        return ["postgresql"]
    else:
        raise Exception(f"Invalid Engine: {engine}")

def get_default_database_name(engine):
    if engine == "aurora-mysql":
        return "default"
    elif engine == "aurora-postgresql":
        return "postgres"
    else:
        raise Exception(f"Invalid Engine: {engine}")

def format_tags(tags_dict):
    return [{"Key": k, "Value": v} for k,v in tags_dict.items()]