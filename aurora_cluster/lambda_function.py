import boto3
import botocore
from botocore.exceptions import ClientError

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
        
        availability_zones = cdef.get("availability_zones") or event.get("aws_info", {}).get("region_availability_zones") or ["us-east-1a", "us-east-1b", "us-east-1c", "us-east-1d", "us-east-1e", "us-east-1f"]
        backup_retention_period = cdef.get("backup_retention_period") or 7
        character_set_name = cdef.get("character_set_name") #We do not recommend you set this parameter
        database_name = cdef.get("database_name") or "default"
        
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

        engine_version = cdef.get("engine_version")
        if engine_version and not eh.state.get("engine_version"):
            eh.add_state({"engine_version": engine_version})

        parameter_group_name = cdef.get("parameter_group_name")
        # if parameter_group_name and not eh.state.get("parameter_group_name"):
        #     eh.add_state({"parameter_group_name": parameter_group_name})

        port = cdef.get("port") or get_default_port(engine)
        master_username = cdef.get("master_username") or "admin"
        master_password = cdef.get("master_password")
        manage_master_user_password = cdef.get("manage_master_user_password") or False
        master_user_secret_kms_key_id = cdef.get("master_user_secret_kms_key_id")
        if not master_password and (not manage_master_user_password):
            eh.perm_error("Must specify master_password", 0)
            eh.add_log("Error, master_password Required", {"definition": cdef}, True)
            return eh.finish()

        option_group_name = cdef.get("option_group_name")
        preferred_backup_window = cdef.get("preferred_backup_window") or "05:12-05:42"
        preferred_maintenance_window = cdef.get("preferred_maintenance_window") or "mon:06:09-mon:06:39"

        replicate_source_arn = cdef.get("replicate_source_arn")
        tags = cdef.get("tags") or {}
        storage_encrypted = cdef.get("storage_encrypted", True)

        kms_key_id = cdef.get("kms_key_id")
        pre_signed_url = cdef.get("pre_signed_url")
        enable_iam_authentication = cdef.get("enable_iam_authentication", False)
        backtrack_window = cdef.get("backtrack_window", 0)
        enable_cloudwatch_logs_exports = cdef.get("enable_cloudwatch_logs_exports", get_default_logs_exports(engine))
        
        engine_mode = cdef.get("engine_mode", "provisioned")
        scaling_configuration = cdef.get("scaling_configuration")
        
        deletion_protection = cdef.get("deletion_protection", False)
        global_cluster_identifier = cdef.get("global_cluster_identifier")
        copy_tags_to_snapshot = cdef.get("copy_tags_to_snapshot", False)

        activty_directory_id = cdef.get("activty_directory_id")
        activty_directory_role_name = cdef.get("activty_directory_role_name")

        enable_global_write_forwarding = cdef.get("enable_global_write_forwarding", False)


        storage_type = cdef.get("storage_type", "aurora")
        if storage_type not in ["aurora", "aurora-iopt1"]:
            eh.perm_error("Invalid Storage Type", 0)
            eh.add_log("Error, Invalid Storage Type", {"storage_type": storage_type}, True)
            return eh.finish()

        enable_local_write_forwarding = cdef.get("enable_local_write_forwarding", False)

        apply_changes_immediately = cdef.get("apply_changes_immediately", False)

        pass_back_data = event.get("pass_back_data", {})
        if pass_back_data:
            pass

        elif event.get("op") == "upsert":
            eh.add_op("get_subnet_group")
            if not eh.state.get("engine_version"):
                eh.add_op("get_engine_version")
            eh.add_op("get_cluster")

        elif event.get("op") == "delete":
            eh.add_op("delete_cluster")
        
        initial_attributes = remove_none_attributes({
            "AvailabilityZones": availability_zones,
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
            "OptionGroupName": option_group_name,
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
            "EnableLocalWriteForwarding": enable_local_write_forwarding
        })

        get_subnet_group(subnet_ids)
        create_subnet_group(name)
        initial_attributes["DBSubnetGroupName"] = eh.props.get("subnet_group_name")

        # Note that updating the engine version will cause an outage.
        # Each deployment will auto-update the engine version during the downtime window
        get_engine_version(engine)
        initial_attributes["EngineVersion"] = eh.state.get("engine_version")


        # attributes = {k:str(v) for k,v in attributes.items() if not isinstance(v, dict)}
        print(initial_attributes)

        get_cluster(prev_state, initial_attributes, region)
        create_cluster(initial_attributes, region)
        update_cluster(prev_state, initial_attributes, region, apply_changes_immediately)
        delete_cluster(prev_state)

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
                    "subnet_group_name": subnet_group.get("DBSubnetGroupName")
                })
                return None
    
    # If we get here, we need to create a new subnet group
    eh.add_op("create_subnet_group", {"subnet_ids": subnet_ids})

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
        )
        eh.add_props({
            "subnet_group_arn": subnet_group_retval.get("DBSubnetGroupArn"),
            "subnet_group_name": subnet_group_retval.get("DBSubnetGroupName")
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

        #Get the latest version of this engine
        max_version_number = max([float(version.get("EngineVersion").replace(".", "")) for version in engine_version_retval.get("DBEngineVersions")])
        version_to_use = list([version for version in engine_version_retval.get("DBEngineVersions") if float(version.get("EngineVersion").replace(".", "")) == max_version_number])[0].get("EngineVersion")
        eh.add_log("Selected Engine Version", {"All Versions": engine_version_retval, "Used Version": version_to_use})

        eh.add_state({
            "engine_version": version_to_use
        })
    except ClientError as e:
        handle_common_errors(e, eh, "Get Engine Versions Failed", 0)

@ext(handler=eh, op="get_cluster")
def get_cluster(prev_state, attributes, region):
    try:
        identifier_to_find = prev_state.get("props", {}).get("name") or attributes["DBClusterIdentifier"]
        cluster_retval = rds.describe_db_clusters(
            DBClusterIdentifier=identifier_to_find
        ).get("DBClusters")[0]

        eh.add_log("Got Cluster", cluster_retval)

        for attrib_key, attrib_value in attributes.items():
            if attrib_key == "Tags":
                current_tags_dict = {tag.get("Key"): tag.get("Value") for tag in cluster_retval.get(attrib_key)}
                desired_tags_dict = {tag.get("Key"): tag.get("Value") for tag in attrib_value}
                if current_tags_dict != desired_tags_dict:
                    eh.add_log("Tags Don't Match", {"current_tags": current_tags_dict, "desired_tags": desired_tags_dict})
                    update_tags = {k:v for k,v in desired_tags_dict.items() if ((k not in current_tags_dict) or (v != current_tags_dict.get(k)))}
                    remove_tags = [k for k in current_tags_dict if k not in desired_tags_dict]
                    if update_tags:
                        eh.add_op("add_tags", update_tags)
                    if remove_tags:
                        eh.add_op("remove_tags", remove_tags)

            if attrib_value != cluster_retval.get(attrib_key):
                if attrib_key in ["DBSubnetGroupName", "Engine"]:
                    eh.add_log(f"Cannot Change Subnets or Engine", {"attributes": attributes, "cluster_retval": cluster_retval})
                    eh.perm_error(f"Cannot Change Subnets or Engine", 2)
                    return None
                print(f"attrib_key = {attrib_key}, attrib_value = {attrib_value}, cluster_retval.get(attrib_key) = {cluster_retval.get(attrib_key)}")
                eh.add_log("Cluster Attributes Don't Match", {"attrib_key": attrib_key, "attrib_value": attrib_value, "cluster_attrib_value": cluster_retval.get(attrib_key)})
                eh.add_op("update_cluster")
                return None

        eh.add_log("Cluster Attributes Match", {"attributes": attributes, "cluster_retval": cluster_retval})
        update_props_and_links(eh, region, cluster_retval)

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

    except ClientError as e:
        handle_common_errors(e, eh, "Create Cluster Failed", 15)

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
                "ServerlessV2ScalingConfiguration", "NetworkType", "ManageMasterUserPassword", "RotateMasterUserPassword", "MasterUserSecretKmsKeyId", "EngineMode", "AllowEngineModeChange", 
                "EnableLocalWriteForwarding", "AwsBackupRecoveryPointArn"]
            }
        ).get("DBCluster")

        eh.add_log("Updated Cluster", cluster_retval)

        update_props_and_links(eh, region, cluster_retval)

    except ClientError as e:
        handle_common_errors(e, eh, "Update Cluster Failed", 15)

@ext(handler=eh, op="delete_cluster")
def delete_cluster(prev_state):
    try:
        cluster_retval = rds.delete_db_cluster(
            DBClusterIdentifier=prev_state.get("props", {}).get("name"),
            SkipFinalSnapshot=True
        ).get("DBCluster")

        eh.add_log("Deleted Cluster", cluster_retval)
    except ClientError as e:
        if e.response['Error']['Code'] in ["DBClusterNotFoundFault"]:
            eh.add_log("Cluster Not Found, Exiting", {"name": prev_state.get("props", {}).get("name")})
        else:
            handle_common_errors(e, eh, "Delete Cluster Failed", 15)

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

def format_tags(tags_dict):
    return [{"Key": k, "Value": v} for k,v in tags_dict.items()]