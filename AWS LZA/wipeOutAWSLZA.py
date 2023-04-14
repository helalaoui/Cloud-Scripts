############################################################################
#          Wipe-Out Script of the AWS Landing Zone Accelerator (LZA)
#
#    ******************   USE AT YOUR OWN RISK !!! *****************
#
# Script in 3 phases:
#
#  The context for execution of this script should already have a valid
#    AWS authentication context: .aws/credentials and .aws/config
#
#  Version 0.2 - 2023-04-12
#  Author: Hicham El Alaoui - alaoui@rocketmail.com
#
############################################################################

from datetime import datetime
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
    "ca-central-1"
]

root_account = "1111111111111111"
root_profile = "default"

# List of non-root accounts and their profile name
lza_non_root_accounts = {
    "222222222222": "Journalisation",
}

lza_security_account_id = "126235163086"

# Message verbose level you want. Options: VERBOSE_NONE, VERBOSE_LOW, VERBOSE_MEDIUM,
#    or VERBOSE_HIGH. Recommended: VERBOSE_LOW.
requested_verbose_level = VERBOSE_LOW

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

lza_tag_name = 'Accelerator'
lza_tag_value = 'AWSAccelerator'

lza_log_group_name_prefix = '/aws/lambda/AWSAccelerator'

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
def delete_stack(**kwargs):
    cloudformation = kwargs['cloudformation_client']
    stack_name = kwargs['stack_name']
    wait_till_deleted = kwargs['wait_till_deleted']
    delete_waiter = kwargs['waiter']
    
    try:
        vprint(f"\tDisabling Termination Protection on stack {stack_name}", VERBOSE_MEDIUM)
        response = cloudformation.update_termination_protection(EnableTerminationProtection=False, StackName=stack_name)
        vprint(response, VERBOSE_HIGH)

        vprint(f"\tStarting Deletion of the {stack_name} stack", VERBOSE_MEDIUM)
        cloudformation.delete_stack(StackName=stack_name)

        if wait_till_deleted:
            vprint(f"\tWaiting for stack {stack_name} to finish deleting ...", VERBOSE_LOW)
            delete_waiter.wait(StackName=stack_name)
            vprint(f"\tStack {stack_name} deleted ...", VERBOSE_LOW)
    except ClientError as err:
        vprint('*'*20 + f"Unable to delete Stack {stack_name}. Error message:", VERBOSE_LOW)
        vprint(err, VERBOSE_LOW)

    return

############################################################################
# Empty and delete a Bucket:
def delete_bucket(**kwargs):
    s3 = kwargs['s3_resource']
    bucket_name = kwargs['bucket_name']

    vprint(f"Deleting bucket {bucket_name} ...", VERBOSE_LOW)

    try:    
        bucket_versioning = s3.BucketVersioning(bucket_name)
        vprint(f"\tDeleting all objects in bucket {bucket_name} (bucket versioning {bucket_versioning.status})", VERBOSE_MEDIUM)
    except ClientError as err:
        vprint(f"\tBucket Not Found!", VERBOSE_LOW)
        vprint('*'*20 + f" Error message:", VERBOSE_MEDIUM)
        vprint(err, VERBOSE_MEDIUM)
        return

    try:
        bucket = s3.Bucket(bucket_name)
        if bucket_versioning.status == 'Enabled':
            bucket.object_versions.delete()
        else:
            bucket.objects.all().delete()

        vprint(f"\tStarting deletion of bucket {bucket_name}", VERBOSE_MEDIUM)
        bucket.delete()
            
    except ClientError as err:
        vprint('*'*20 + f" Unable to delete bucket {bucket_name}. Error message:", VERBOSE_LOW)
        vprint(err, VERBOSE_LOW)
    
    return

############################################################################
# Get an ECR repository:
def get_ecr_repo(**kwargs):
    ecr = kwargs['ecr_client']
    repo_name = kwargs['repo_name']

    try:    
        response = ecr.describe_repositories(repositoryNames = [repo_name])
    except ClientError as err:
        return None

    return response['repositories'][0]

############################################################################
# Delete an ECR repository:
def delete_ecr_repo(**kwargs):
    ecr = kwargs['ecr_client']
    repo_name = kwargs['repo_name']

    vprint(f"Deleting ECR Repository {repo_name} ...", VERBOSE_LOW)
    try:    
        ecr.delete_repository(repositoryName=repo_name, force=True)
            
    except ClientError as err:
        vprint('*'*20 + f" Unable to delete ECR repository {repo_name}. Error message:", VERBOSE_LOW)
        vprint(err, VERBOSE_LOW)
    
    return

############################################################################
# Delete all KMS keys having a special tag:
def delete_keys_by_tag(**kwargs):
    kms = kwargs['kms_client']
    target_tag_name = kwargs['tag_name']
    target_tag_value = kwargs['tag_value']

    vprint(f"Deleting all KMS keys with tag {target_tag_name} = '{target_tag_value}'...", VERBOSE_MEDIUM)
    
    keys_response = kms.list_keys(Limit=1000)
    
    if keys_response['Keys']:
        target_key_found = False

        try:
            for key in keys_response['Keys']:
                key_id = key['KeyId']
                
                # Check if this is an AWS- or Customer- managed key:
                key_response = kms.describe_key(KeyId = key_id)
                
                if key_response['KeyMetadata']['KeyManager'] == 'AWS':
                    # This is an AWS-Managed key. Ignore.
                    vprint(f"\tIgnoring AWS-managed KMS key {key_id} ...", VERBOSE_MEDIUM)
                    continue

                if key_response['KeyMetadata']['KeyState'] != 'Enabled':
                    vprint(f"\tIgnoring KMS key {key_id} (not in 'Enabled' state) ...", VERBOSE_MEDIUM)
                    continue

                # Get the list of tags of this key:
                tags_response = kms.list_resource_tags(KeyId = key_id)
                
                if tags_response['Tags']:
                    # Check if one of the tags matches the target tag
                    for tag in tags_response['Tags']:
                        if tag['TagKey'] == target_tag_name:
                            if tag['TagValue'] == target_tag_value:
                                target_key_found = True
                                vprint(f"Scheduling deletion of KMS key {key_id} ...", VERBOSE_LOW)
                                delete_response = kms.schedule_key_deletion(KeyId = key_id, PendingWindowInDays=7)
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
def detach_and_detlete_scp(**kwargs):
    organizations = kwargs['organizations_client']
    policy_id = kwargs['policy_id']
    policy_name = kwargs['policy_name']

    # Detach all targets from this policy:
    targets = organizations.list_targets_for_policy(PolicyId = policy_id)

    policy_is_attached = False
    if targets['Targets']:
        for target in targets['Targets']:
            try:
                vprint(f"\tDetaching SCP {policy_name} from target {target['Name']} ...", VERBOSE_MEDIUM)
                organizations.detach_policy(PolicyId = policy_id, TargetId = target['TargetId'])
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
        organizations.delete_policy(PolicyId = policy_id)
    except ClientError as err:
        vprint(f"Unable to delete AWS Organizations SCP {policy_name}. Error Message:", VERBOSE_LOW)
        vprint(err, VERBOSE_LOW)

    return


############################################################################
#                         Start of the Script
############################################################################
# Basic Checks:
if lza_security_account_id not in lza_non_root_accounts:
    vprint(f"Security account ID '{lza_security_account_id}' not found in the provided list of accounts!\nPlease check the value of the lza_security_account_id parameter in the parameters section of this script.\nAborting.")
    exit(1)

############################################################################
#                 Phase 1: Delete the LZA SCPs
############################################################################
vprint('\n' + '='*30 + " Phase 1: Delete the LZA SCPs " + '='*30, VERBOSE_LOW)

organizations = boto3.client('organizations')
response = organizations.list_policies(Filter='SERVICE_CONTROL_POLICY')

lza_scp_found = False
for policy in response['Policies']:
    if policy['Name'].startswith('AWSAccelerator-'):
        detach_and_detlete_scp(organizations_client = organizations, policy_id = policy['Id'], policy_name = policy['Name'])
        lza_scp_found = True

if not lza_scp_found:
    vprint("There are no LZA SCPs to delete!", VERBOSE_LOW)


############################################################################

aws_sessions = {}
aws_sessions[(root_account, 'us-east-1')] = boto3.session.Session(profile_name = root_profile, region_name = 'us-east-1')

for region in regions:
    
    # Build the list of accounts:
    all_lza_accounts = [(account_id, account_name) for account_id, account_name in lza_non_root_accounts.items()]
    all_lza_accounts.append((root_account, root_profile))
    vprint("All LZA Accounts:", VERBOSE_MEDIUM)
    vprint(all_lza_accounts, VERBOSE_MEDIUM)
    
    
    # Opening sessions for all the accounts and regions
    for account_id, account_name in all_lza_accounts:
        aws_sessions[(account_id, region)] = boto3.session.Session(profile_name=account_name, region_name=region)

    ############################################################################

    for account_id, account_name in lza_non_root_accounts.items():
        vprint('\n' + '='*80 + '\n' + ' '*20 + f"Cleaning Account {account_name} ({account_id}) in region {region}\n" + '='*80, VERBOSE_LOW)
        
        ############################################################################
        #                 Phase 2: Delete AWSAccelerator-xxxxx Stacks
        ############################################################################
        vprint('\n' + '='*30 + " Phase 2: Delete the LZA core stacks (AWSAccelerator-xxxxx) " + '='*30, VERBOSE_LOW)

        cloudformation = aws_sessions[(account_id, region)].client('cloudformation')
        delete_waiter = cloudformation.get_waiter('stack_delete_complete')
        
        stacks_to_delete = []
        stacks_found = False
        stack_to_wait = None
        for stack in lza_core_stacks:
            stack_name = f"{stack}-{account_id}-{region}"
            vprint(f"Deleting the {stack_name} stack in the '{account_name}' account in region {region}", VERBOSE_LOW)
            stacks_to_delete.append(stack_name)

            # Check if the stack exists and is in a COMPLETE state:
            try:
                stack_response = cloudformation.describe_stacks(StackName = stack_name)
            except ClientError as err:
                vprint(f"\tStack Not Found: {stack_name}.", VERBOSE_LOW)
                vprint('*'*20 + f"Could not find stack {stack_name}. Error message:", VERBOSE_HIGH)
                vprint(err, VERBOSE_HIGH)
                continue

            stacks_found = True
            
            stack_status = stack_response['Stacks'][0]['StackStatus']
            if stack_status not in ['CREATE_COMPLETE', 'UPDATE_COMPLETE']:
                vprint(f"\tStack status '{stack_status}' is not CREATE_COMPLETE nor UPDATE_COMPLETE. Skipping ...", VERBOSE_LOW)
                continue
            
            delete_stack(
                cloudformation_client = cloudformation,
                stack_name = stack_name,
                wait_till_deleted = False,
                waiter = delete_waiter
            )
            
            stack_to_wait = stack_name
        
        if stacks_found:
            while stack_to_wait:
                vprint(f"... Waiting for stack {stack_to_wait} to finish deleting ...", VERBOSE_LOW)
                delete_waiter.wait(StackName = stack_to_wait)
                vprint(f"\tStack {stack_to_wait} completed deletion ...", VERBOSE_LOW)

                # Check if there are other stack still being deleted
                stack_to_wait = None
                response = cloudformation.list_stacks(StackStatusFilter=['DELETE_IN_PROGRESS']) 
                for stack in response['StackSummaries']:
                    if stack_name in stacks_to_delete:
                        stack_to_wait = stack_name
                        break
            
            vprint(f">>> All LZA core stacks in account '{account_name}' were deleted ...", VERBOSE_LOW)

        else:
            vprint(f"There are no LZA core stacks to delete in account '{account_name}'!", VERBOSE_LOW)

        ############################################################################
        #           Phase 3: Delete the AWSAccelerator-CDKToolkit stack
        ############################################################################
        stack_name = lza_cdk_stack
        vprint('\n' + '='*30 + " Phase 3: Delete the {stack_name} stack in account '{account_name}'" + '='*30, VERBOSE_LOW)

        # Check if the stack exists and is in a COMPLETE state:
        try:
            stack_response = cloudformation.describe_stacks(StackName = stack_name)
        except ClientError as err:
            vprint(f"\tStack Not Found: {stack_name}.", VERBOSE_LOW)
            vprint('*'*20 + f"Could not find stack {stack_name}. Error message:", VERBOSE_HIGH)
            vprint(err, VERBOSE_HIGH)
        else:
            stack_status = stack_response['Stacks'][0]['StackStatus']
            if stack_status not in ['CREATE_COMPLETE', 'UPDATE_COMPLETE']:
                vprint(f"\tStack status '{stack_status}' is not CREATE_COMPLETE nor UPDATE_COMPLETE. Skipping ...", VERBOSE_LOW)
            else:
                delete_stack(
                    cloudformation_client = cloudformation,
                    stack_name = stack_name,
                    wait_till_deleted = True,
                    waiter = delete_waiter
                )
            
        ############################################################################
        #           Phase 4: Delete the LZA S3 Buckets
        ############################################################################
        vprint('\n' + '='*30 + f" Phase 4: Delete the LZA S3 Buckets in account '{account_name}'" + '='*30, VERBOSE_LOW)
        
        buckets_to_delete = [f"aws-accelerator-{bucket}-{account_id}-{region}" for bucket in lza_buckets]
        buckets_to_delete += [f"cdk-accel-assets-{account_id}-{region}"]

        s3_resource = aws_sessions[(account_id, region)].resource('s3')
        for bucket_name in buckets_to_delete:
            delete_bucket(s3_resource = s3_resource, bucket_name = bucket_name)

        ############################################################################
        #           Phase 5: Delete the LZA ECR Repository (CDK)
        ############################################################################
        vprint('\n' + '='*30 + f" Phase 5: Delete the LZA ECR Repository (CDK) in account '{account_name}'" + '='*30, VERBOSE_LOW)

        ecr = aws_sessions[(account_id, region)].client('ecr')
        cdk_repo = f"cdk-accel-container-assets-{account_id}-{region}"

        if get_ecr_repo(ecr_client = ecr, repo_name = cdk_repo):
            delete_ecr_repo(ecr_client = ecr, repo_name = cdk_repo)
        else:
            vprint(f"There is no LZA ECR Repository (CDK)!", VERBOSE_LOW)
        
        ############################################################################
        #           Phase 6: Delete the LZA KMS keys
        ############################################################################
        vprint('\n' + '='*30 + f" Phase 6: Delete the LZA KMS keys in account '{account_name}'" + '='*30, VERBOSE_LOW)

        kms = aws_sessions[(account_id, region)].client('kms')

        delete_keys_by_tag(kms_client = kms, tag_name = lza_tag_name, tag_value = lza_tag_value)
        

############################################################################
#           Phase 7: Delete the Root Account-specific stacks
############################################################################
vprint('\n' + '='*30 + f" Phase 7: Delete the Root Account-specific stacks " + '='*30, VERBOSE_LOW)

account_id = root_account
stacks_found = False

###########################################
# Delete the root account stacks in regions
for region in regions:
    cloudformation = aws_sessions[(account_id, region)].client('cloudformation')
    delete_waiter = cloudformation.get_waiter('stack_delete_complete')
    
    for stack in lza_core_stacks + lza_root_stacks_in_region:
        stack_name = f"{stack}-{account_id}-{region}"
        vprint(f"Deleting the {stack_name} stack in the ROOT account in region {region}", VERBOSE_LOW)

        # Check if the stack exists and is in a COMPLETE state:
        try:
            stack_response = cloudformation.describe_stacks(StackName = stack_name)
        except ClientError as err:
            vprint(f"\tStack Not Found: {stack_name}.", VERBOSE_LOW)
            vprint('*'*20 + f"Could not find stack {stack_name}. Error message:", VERBOSE_HIGH)
            vprint(err, VERBOSE_HIGH)
            continue

        stacks_found = True
        
        stack_status = stack_response['Stacks'][0]['StackStatus']
        if stack_status not in ['CREATE_COMPLETE', 'UPDATE_COMPLETE']:
            vprint(f"\tStack status '{stack_status}' is not CREATE_COMPLETE nor UPDATE_COMPLETE. Skipping ...", VERBOSE_LOW)
            continue
        
        delete_stack(
            cloudformation_client = cloudformation,
            stack_name = stack_name,
            wait_till_deleted = True,
            waiter = delete_waiter
        )
        

###########################################
#  Delete the root account stacks specific to 'us-east-1'
region = 'us-east-1'
cloudformation = aws_sessions[(account_id, region)].client('cloudformation')
delete_waiter = cloudformation.get_waiter('stack_delete_complete')

for stack in lza_root_stacks_in_us_east_1:
    stack_name = f"{stack}-{account_id}-{region}"
    vprint(f"Deleting the {stack_name} stack in the ROOT account in region {region}", VERBOSE_LOW)

    # Check if the stack exists and is in a COMPLETE state:
    try:
        stack_response = cloudformation.describe_stacks(StackName = stack_name)
    except ClientError as err:
        vprint(f"\tStack Not Found: {stack_name}.", VERBOSE_LOW)
        vprint('*'*20 + f"Could not find stack {stack_name}. Error message:", VERBOSE_HIGH)
        vprint(err, VERBOSE_HIGH)
        continue

    stacks_found = True
    
    stack_status = stack_response['Stacks'][0]['StackStatus']
    if stack_status not in ['CREATE_COMPLETE', 'UPDATE_COMPLETE']:
        vprint(f"\tStack status '{stack_status}' is not CREATE_COMPLETE nor UPDATE_COMPLETE. Skipping ...", VERBOSE_LOW)
        continue
    
    delete_stack(
        cloudformation_client = cloudformation,
        stack_name = stack_name,
        wait_till_deleted = True,
        waiter = delete_waiter
    )

###########################################
#  Delete the CDKToolkit stack in the Root account and 'us-east-1' region
stack_name = 'CDKToolkit'
vprint(f"Deleting the {stack_name} stack in the ROOT account in region {region}", VERBOSE_LOW)

# Check if the stack exists and is in a COMPLETE state:
cdk_found = False
try:
    stack_response = cloudformation.describe_stacks(StackName = stack_name)
except ClientError as err:
    vprint(f"\tStack Not Found: {stack_name}.", VERBOSE_LOW)
    vprint('*'*20 + f"Could not find stack {stack_name}. Error message:", VERBOSE_HIGH)
    vprint(err, VERBOSE_HIGH)
else:
    cdk_found = True

if cdk_found:
    stacks_found = True

    stack_status = stack_response['Stacks'][0]['StackStatus']
    if stack_status in ['CREATE_COMPLETE', 'UPDATE_COMPLETE']:
        delete_stack(
            cloudformation_client = cloudformation,
            stack_name = stack_name,
            wait_till_deleted = True,
            waiter = delete_waiter
        )
    else:
        vprint(f"\tStack status '{stack_status}' is not CREATE_COMPLETE nor UPDATE_COMPLETE. Skipping ...", VERBOSE_LOW)

if not stacks_found:
    vprint(f"There are no root-specific stacks to delete!", VERBOSE_LOW)

############################################################################
#           Phase 8: Delete the Root-specific LZA S3 Buckets
############################################################################
vprint('\n' + '='*30 + f" Phase 8: Delete the Root-specific LZA S3 Buckets " + '='*30, VERBOSE_LOW)

buckets_to_delete = [f"aws-accelerator-{bucket}-{account_id}-{region}" for bucket in lza_root_buckets]
buckets_to_delete += [f"cdk-accel-assets-{account_id}-{region}"]
buckets_to_delete += [f"cdk-accel-assets-{account_id}-us-east-1"]

s3_resource = aws_sessions[(account_id, region)].resource('s3')
for bucket_name in buckets_to_delete:
    delete_bucket(s3_resource = s3_resource, bucket_name = bucket_name)


############################################################################
#           Phase 9: Clean the 'Security' Account
############################################################################
for region in regions:
    vprint('\n' + '='*30 + f" Phase 9: Clean the 'Security' Account in region '{region}' " + '='*30, VERBOSE_LOW)

    ssm = aws_sessions[ (lza_security_account_id, region) ].client('ssm')
    
    response = ssm.describe_parameters(
        ParameterFilters=[
            {
                'Key': f"tag:{lza_tag_name}",
                'Values': [ f"{lza_tag_value}" ]
            }
        ],
        MaxResults = 50
    )

    for parameter in response['Parameters']:
        vprint(f"Deleting parameter '{parameter['Name']}'", VERBOSE_LOW)
        ssm.delete_parameter(Name = parameter['Name'])

    logs = aws_sessions[ (lza_security_account_id, region) ].client('logs')
    
    response = logs.describe_log_groups(
        logGroupNamePrefix = lza_log_group_name_prefix
        )
    
    for log_group in response['logGroups']:
        vprint(f"Deleting Log Group '{log_group['logGroupName']}'", VERBOSE_LOW)
        logs.delete_log_group(logGroupName = log_group['logGroupName'])


############################################################################
#                Phase 10: Rename the CodeCommit Repo
############################################################################
for region in regions:
    vprint('\n' + '='*30 + f" Phase 10: Rename the CodeCommit Repo in region '{region}' " + '='*30, VERBOSE_LOW)

    codecommit = aws_sessions[ (root_account, region) ].client('codecommit')
    
    try:
        response = codecommit.get_repository(repositoryName = lza_repository_name)
    except ClientError as err:
        vprint(f"CodeCommit Repository {lza_repository_name} Not Found!", VERBOSE_LOW)
        vprint(err, VERBOSE_HIGH)
    else:
        now = datetime.now()
        new_name = lza_repository_name + '_' + now.strftime("%Y-%m-%d_%Hh%Mm%Ss")
        vprint(f"Renaming the '{lza_repository_name}' repository to '{new_name}'")
        codecommit.update_repository_name(oldName = lza_repository_name, newName = new_name)



vprint(f"\nAWS LZA Wipe-Out Ended", VERBOSE_LOW)