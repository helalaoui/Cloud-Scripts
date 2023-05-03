from datetime import datetime
# AWS SDK for Python modules:
import boto3
from botocore.exceptions import ClientError

# Constants - Do not modify
VERBOSE_NONE   = 1
VERBOSE_LOW    = 2
VERBOSE_MEDIUM = 3
VERBOSE_HIGH   = 4

############################################################################
#                                User Parameters
############################################################################

regions = [
    # "us-east-1",
    "ca-central-1",
]

root_account = "00000000000000"
root_profile = "default"

# List of non-root accounts and their profile name
# The profile name references the section for that account in the .aws/config file.
lza_non_root_accounts = {
    "11111111111": "Securite",
}

# The security account that needs to be cleaned in step 5:
lza_security_account_id = "11111111111"

# Message verbose level you want. Options: VERBOSE_NONE, VERBOSE_LOW, VERBOSE_MEDIUM,
#    or VERBOSE_HIGH. Recommended: VERBOSE_LOW.
requested_verbose_level = VERBOSE_HIGH

############################################################################
#                            LZA Internal Parameters
############################################################################

lza_core_stacks = [
    "AWSAccelerator-CustomizationsStack",
    "AWSAccelerator-NetworkAssociationsStack",
    "AWSAccelerator-NetworkAssociationsGwlbStack",
    "AWSAccelerator-NetworkVpcDnsStack",
    "AWSAccelerator-NetworkVpcEndpointsStack",
    "AWSAccelerator-SecurityResourcesStack",
    "AWSAccelerator-NetworkVpcStack",
    "AWSAccelerator-OperationsStack",
    "AWSAccelerator-NetworkPrepStack",
    "AWSAccelerator-SecurityStack",
    "AWSAccelerator-LoggingStack"
]

lza_root_stacks_in_region = [
    "AWSAccelerator-OrganizationsStack",
    "AWSAccelerator-PrepareStack",
    "AWSAccelerator-PipelineStack",
    "awsaccelerator-installerstack"
]

lza_root_stacks_in_us_east_1 = [
    "AWSAccelerator-FinalizeStack",
    "AWSAccelerator-AccountsStack"
]

lza_cdk_stack = 'AWSAccelerator-CDKToolkit'

lza_buckets = [
    "s3-access-logs"
]

lza_root_buckets = [
    "assets",
    "assets-logs",
    "cur",
    "installer",
    "pipeline",
    "s3-logs"
]

lza_scp_name_prefix = 'AWSAccelerator-'

lza_tag_name = 'Accelerator'
lza_tag_value = 'AWSAccelerator'

lza_log_group_name_prefix = '/aws/lambda/AWSAccelerator'

lza_cost_n_report_name = 'accelerator-cur'

lza_repository_name = 'aws-accelerator-config'

############################################################################
#                     End of LZA Internal Parameters
############################################################################

############################################################################
# Verbose Print
def vprint(message, message_verbose_level=VERBOSE_LOW):
    if message_verbose_level <= requested_verbose_level:
        print(message)
    return

############################################################################
# Delete a CloudFormation Stack
def delete_stack(cloudformation_client, stack_name, wait_till_deleted=False, waiter=None):
    vprint(f"Deleting the {stack_name} stack ...", VERBOSE_MEDIUM)
    # Check if the stack exists and is in a COMPLETE state:
    try:
        stack_response = cloudformation_client.describe_stacks(StackName = stack_name)
    except ClientError as err:
        vprint(f"\tStack Not Found: {stack_name}.", VERBOSE_MEDIUM)
        vprint('*'*20 + f"Error message:", VERBOSE_HIGH)
        vprint(err, VERBOSE_HIGH)
        return False

    stack_status = stack_response['Stacks'][0]['StackStatus']
    # if stack_status not in ['CREATE_COMPLETE', 'UPDATE_COMPLETE']:
    #     vprint(f"\tStack {stack_name} has a status of '{stack_status}' which is not CREATE_COMPLETE nor UPDATE_COMPLETE. Skipping ...", VERBOSE_LOW)
    #     return False
    
    try:
        vprint(f"\tDisabling Termination Protection on stack {stack_name}", VERBOSE_MEDIUM)
        response = cloudformation_client.update_termination_protection(EnableTerminationProtection=False, StackName=stack_name)
        vprint(response, VERBOSE_HIGH)

        vprint(f"Starting Deletion of the {stack_name} stack", VERBOSE_LOW)
        cloudformation_client.delete_stack(StackName=stack_name)

        if wait_till_deleted:
            vprint(f"\tWaiting for stack {stack_name} to finish deleting ...", VERBOSE_LOW)
            waiter.wait(StackName=stack_name)
            vprint(f"\tStack {stack_name} deleted ...", VERBOSE_LOW)
        return True
    except ClientError as err:
        vprint(f"\tUnable to delete Stack {stack_name}!", VERBOSE_LOW)
        vprint('*'*20 + f"Error message:", VERBOSE_LOW)
        vprint(err, VERBOSE_LOW)
        return False

############################################################################
# Empty and delete a Bucket:
# Returns True if bucket deleted or False otherwise.
def delete_bucket(s3_resource, bucket_name):
    try:
        vprint(f"\tDeleting all objects in bucket {bucket_name}", VERBOSE_MEDIUM)
        bucket_versioning = s3_resource.BucketVersioning(bucket_name)
    except ClientError as err:
        vprint('*'*20 + f" Bucket Not Found! Error message:", VERBOSE_MEDIUM)
        vprint(err, VERBOSE_MEDIUM)
        return False

    try:
        bucket = s3_resource.Bucket(bucket_name)
        if bucket_versioning.status == 'Enabled':
            bucket.object_versions.delete()
        else:
            bucket.objects.all().delete()
        vprint(f"Deleting bucket {bucket_name} ...", VERBOSE_LOW)
        bucket.delete()
    except ClientError as err:
        vprint('*'*20 + f" Unable to delete bucket {bucket_name}. Error message:", VERBOSE_LOW)
        vprint(err, VERBOSE_LOW)
        return False
    else:
        return True
    
############################################################################
# Delete an ECR repository:
def delete_ecr_repo(ecr_client, repo_name):
    vprint(f"Deleting ECR Repository {repo_name} ...", VERBOSE_MEDIUM)
    try:    
        response = ecr_client.describe_repositories(repositoryNames = [repo_name])
    except ClientError as err:
        vprint('*'*20 + f" ECR Repository {repo_name} Not Found! Error message:", VERBOSE_MEDIUM)
        vprint(err, VERBOSE_MEDIUM)
        return False

    try:    
        ecr_client.delete_repository(repositoryName=repo_name, force=True)
            
    except ClientError as err:
        vprint('*'*20 + f" Unable to delete ECR repository {repo_name}. Error message:", VERBOSE_LOW)
        vprint(err, VERBOSE_LOW)
        return False
    else:
        return True

############################################################################
# Delete all KMS keys having a given tag:
def delete_keys_by_tag(kms_client, target_tag_name, target_tag_value):
    vprint(f"Deleting all KMS keys with tag {target_tag_name} = '{target_tag_value}'...", VERBOSE_MEDIUM)
    
    keys_response = kms_client.list_keys(Limit=1000)
    
    if keys_response['Keys']:
        target_key_found = False

        try:
            for key in keys_response['Keys']:
                key_id = key['KeyId']
                
                # Check if this is an AWS- or Customer- managed key:
                key_response = kms_client.describe_key(KeyId = key_id)
                
                if key_response['KeyMetadata']['KeyManager'] == 'AWS':
                    # This is an AWS-Managed key. Ignore.
                    vprint(f"\tIgnoring AWS-managed KMS key {key_id} ...", VERBOSE_MEDIUM)
                    continue

                if key_response['KeyMetadata']['KeyState'] != 'Enabled':
                    vprint(f"\tIgnoring KMS key {key_id} (not in 'Enabled' state) ...", VERBOSE_MEDIUM)
                    continue

                # Get the list of tags of this key:
                tags_response = kms_client.list_resource_tags(KeyId = key_id)
                
                if tags_response['Tags']:
                    # Check if one of the tags matches the target tag
                    for tag in tags_response['Tags']:
                        if tag['TagKey'] == target_tag_name:
                            if tag['TagValue'] == target_tag_value:
                                target_key_found = True
                                vprint(f"Scheduling deletion of KMS key {key_id} ...", VERBOSE_LOW)
                                delete_response = kms_client.schedule_key_deletion(KeyId = key_id, PendingWindowInDays=7)
                                vprint(f"\tDeletion scheduled for '{delete_response['DeletionDate']}' GW.", VERBOSE_LOW)
                            else:
                                vprint(f"\tKMS key {key_id} has a '{target_tag_name}' tag but not with the target value. Actual tag value = '{tag['TagValue']}', target tag value = '{target_tag_value}'.Skipping ...", VERBOSE_LOW)
                        else:
                            vprint(f"\tIrrelevant tag {tag['TagKey']}. Skipping  ...", VERBOSE_HIGH)
                
        except ClientError as err:
            vprint('*'*20 + f" Unable to delete KMS keys. Error message:", VERBOSE_LOW)
            vprint(err, VERBOSE_LOW)

        if not target_key_found:
            vprint(f"There are no tags with name '{target_tag_name}' and value '{target_tag_value}'!", VERBOSE_LOW)
        
    else:
        vprint(f"There are no KMS keys in this account.", VERBOSE_LOW)

    
    return

############################################################################
# Detach and Delete an SCP policy
def detach_and_delete_scp(organizations_client, policy_id, policy_name):
    # Detach all targets from this policy:
    targets = organizations_client.list_targets_for_policy(PolicyId = policy_id)

    policy_is_attached = False
    if targets['Targets']:
        for target in targets['Targets']:
            try:
                vprint(f"\tDetaching SCP {policy_name} from target {target['Name']} ...", VERBOSE_MEDIUM)
                organizations_client.detach_policy(PolicyId = policy_id, TargetId = target['TargetId'])
            except ClientError as err:
                vprint(f"Unable to detach SCP {policy_name} from target {target['Name']}. Error Message:", VERBOSE_LOW)
                vprint(err, VERBOSE_LOW)
                policy_is_attached = True
    else:
        policy_is_attached = False
    
    if policy_is_attached:
        vprint(f"Unable to detach AWS Organizations SCP {policy_name}! Skipping ...", VERBOSE_LOW)
        return
    
    vprint(f"Deleting AWS Organizations SCP {policy_name} ...", VERBOSE_LOW)
    try:
        organizations_client.delete_policy(PolicyId = policy_id)
    except ClientError as err:
        vprint(f"Unable to delete AWS Organizations SCP {policy_name}. Error Message:", VERBOSE_LOW)
        vprint(err, VERBOSE_LOW)

    return


############################################################################

region = 'ca-central-1'
aws_session = boto3.session.Session(profile_name = root_profile, region_name = region)

############################################################################
vprint('\n' + '>'*10 + f" Delete the 'Organization' stack ", VERBOSE_LOW)

cloudformation = aws_session.client('cloudformation')
delete_waiter = cloudformation.get_waiter('stack_delete_complete')
stacks_deleted = False

stack_name = f"AWSAccelerator-OrganizationsStack-{root_account}-{region}"

this_stack_deleted = delete_stack(
    cloudformation_client = cloudformation,
    stack_name = stack_name,
    wait_till_deleted = True,
    waiter = delete_waiter
)

############################################################################
vprint('\n' + '>'*10 + f" Delete the Cost and Usage Report Bucket ", VERBOSE_LOW)

buckets_deleted = False

s3_resource = aws_session.resource('s3')
bucket_name = f"aws-accelerator-cur-{root_account}-{region}"
delete_status = delete_bucket(s3_resource = s3_resource, bucket_name = bucket_name)

############################################################################
#      Step 6: Delete the Cost and Usage Report Definition
############################################################################
vprint('\n' + '>'*10 + f" Step 6: Delete the Cost and Usage Report Definition", VERBOSE_LOW)

aws_session = boto3.session.Session(profile_name = root_profile, region_name = 'us-east-1')
cost_usage = aws_session.client('cur')

vprint(f"Deleting Cost and Usage Report {lza_cost_n_report_name} ...", VERBOSE_MEDIUM)
cost_usage.delete_report_definition(
    ReportName = lza_cost_n_report_name
)

