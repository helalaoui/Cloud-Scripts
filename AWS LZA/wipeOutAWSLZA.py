############################################################################
#          Wipe-Out Script of the AWS Landing Zone Accelerator (LZA)
#
#    ******************   USE AT YOUR OWN RISK !!! *****************
#
# Script in steps:
#        1: Delete the LZA SCPs
#        2: Delete the IPAM on the Network Account
#        3: Clean the 'Security' Account
#        4: Clean the Operations Account
#        5: For each account:
#           5a: Delete the 'AWSAccelerator-SessionManagerEC2Role' IAM role
#           5b: Delete the AWSAccelerator-xxxxx Stacks
#           5c: Delete the StackSet-AWSControlTower...... Stacks
#           5d: Delete the LZA S3 Buckets
#           5e: Delete the LZA KMS keys
#           5f: Delete the LZA Log Groups
#        6: Delete the Root Account-specific stacks
#        7: Delete the Root-specific LZA S3 Buckets
#        8: Delete the Cost and Usage Report Definition
#        9: Delete the IAM Policy 'Default-Boundary-Policy'
#       10: Rename the CodeCommit Repo
#       11: Remove service delegations
#       12: Disable Security services
#       13: ControlTower Clean-up
#
#  Please fill-in the Parameters section before running this script.
#
#  The context for execution of this script should already have a valid
#    AWS authentication context: .aws/credentials and .aws/config
#
#  Version 2.0 - 2023-09-27
#  Author: Hicham El Alaoui - alaoui@it-pro.com
#
############################################################################

from datetime import datetime
from time import sleep
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
    "22222222222": "Network",
    "33333333333": "Securite",
    "44444444444": "Operations",
}

# The network account that needs to be cleaned in Step 2:
lza_network_account_id = "22222222222"

# The security account that needs to be cleaned in Step 3:
lza_security_account_id = "33333333333"

# The operations account that needs to be cleaned in Step 4:
lza_operations_account_id = "44444444444"

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
    "AWSAccelerator-SecurityAuditStack",
    "AWSAccelerator-KeyStack",
    "AWSAccelerator-NetworkVpcStack",
    "AWSAccelerator-OperationsStack",
    "AWSAccelerator-NetworkPrepStack",
    "AWSAccelerator-SecurityStack",
    "AWSAccelerator-DependenciesStack",
    "AWSAccelerator-LoggingStack",
]

lza_root_stacks_in_region = [
    "AWSAccelerator-OrganizationsStack",
    "AWSAccelerator-PrepareStack",
    "AWSAccelerator-PipelineStack",
]

lza_installer_stack = "AWSAccelerator-InstallerStack"

lza_root_stacks_in_us_east_1 = [
    "AWSAccelerator-FinalizeStack",
    "AWSAccelerator-AccountsStack"
]

lza_session_manager_ec2_role = "AWSAccelerator-SessionManagerEC2Role"

lza_ipam_tag_name = "accelerator-ipam"

lza_directory_name = "example.local"

lza_buckets = [
    "aws-accelerator-s3-access-logs",
    "aws-accelerator-auditmgr",
    "aws-accelerator-central-logs",
    "aws-accelerator-elb-access-logs",
    # "aws-controltower-logs",
    # "aws-controltower-s3-access-logs",
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

lza_cost_usage_report_name = 'Cost-and-Usage-Report'

lza_repository_name = 'aws-accelerator-config'

lza_log_groups_prefixes = [
    "/AWSAccelerator",
    "/aws/codebuild/AWSAccelerator",
    "/aws/lambda/AWSAccelerator",
    "aws-accelerator",
    "AWSAccelerator",
]

lza_service_linked_roles = [
    "AWSServiceRoleForAmazonGuardDuty",
    "AWSServiceRoleForAmazonMacie",
    "AWSServiceRoleForSecurityHub",
    "AWSServiceRoleForCodeStarNotifications",
    "AWSServiceRoleForAccessAnalyzer",
    "AWSServiceRoleForTrustedAdvisor",
    "AWSServiceRoleForAuditManager",
    "AWSServiceRoleForAutoScaling",
    "AWSServiceRoleForAWSCloud9",
]

control_tower_roles = [
    "AWSControlTowerAdmin",
    "AWSControlTowerCloudTrailRole",
    "AWSControlTowerStackSetRole",
]

control_tower_policies = [
    "AWSControlTowerAdminPolicy",
    "AWSControlTowerCloudTrailRolePolicy",
    "AWSControlTowerStackSetRolePolicy",
]

control_tower_buckets = [
    "aws-controltower-logs",
    "aws-controltower-s3-access-logs",
]

control_tower_log_groups_prefixes = [
    "aws-controltower/CloudTrailLogs",
]

control_tower_service_principal = "controltower.amazonaws.com"

control_tower_events_rules = [
    "awscodestarnotifications-rule",
    "AWSControlTowerManagedRule",
]

############################################################################
#                     End of LZA Internal Parameters
############################################################################


############################################################################
#                     Define Some Useful Functions
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
    if stack_status not in ['CREATE_COMPLETE', 'UPDATE_COMPLETE', 'DELETE_FAILED']:
        vprint(f"\tStack {stack_name} has a status of '{stack_status}' which is not CREATE_COMPLETE nor UPDATE_COMPLETE. Skipping ...", VERBOSE_LOW)
        return False
    
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
        versioning_status = bucket_versioning.status
    except ClientError as err:
        vprint('*'*20 + f" Bucket Not Found! Error message:", VERBOSE_MEDIUM)
        vprint(err, VERBOSE_MEDIUM)
        return False

    try:
        bucket = s3_resource.Bucket(bucket_name)
        if versioning_status == 'Enabled':
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
# Delete an IAM Role:
def delete_iam_role(iam_client, role_name):
    vprint(f"Deleting IAM Role {role_name} ...", VERBOSE_MEDIUM)

    # Check if the role exists
    try:    
        response = iam_client.get_role(RoleName=role_name)
    except ClientError as err:
        vprint('*'*20 + f" IAM Role {role_name} Not Found! Error message:", VERBOSE_MEDIUM)
        vprint(err, VERBOSE_MEDIUM)
        return False
    else:
        vprint(response, VERBOSE_HIGH)

    # Detach all policies from this role:
    try:
        response = iam_client.list_attached_role_policies(RoleName = role_name)
    except ClientError as err:
        vprint(f"Role {role_name} not found! Error Message:", VERBOSE_MEDIUM)
        vprint(err, VERBOSE_MEDIUM)
        return False

    policy_is_attached = False
    if response['AttachedPolicies']:
        for policy in response['AttachedPolicies']:
            try:
                vprint(f"\tDetaching role {role_name} from policy {policy['PolicyName']} ...", VERBOSE_MEDIUM)
                iam_client.detach_role_policy(RoleName = role_name, PolicyArn = policy['PolicyArn'])
            except ClientError as err:
                vprint(f"Unable to detach role {role_name} from policy {policy['PolicyName']}. Error Message:", VERBOSE_LOW)
                vprint(err, VERBOSE_LOW)
                policy_is_attached = True
    else:
        policy_is_attached = False
    
    if policy_is_attached:
        vprint(f"Unable to detach policies from {role_name}! Skipping ...", VERBOSE_LOW)
        return

    # Wait 2 seconds for the state to propagate
    sleep(2)
    
    # Finally delete the role
    try:    
        iam_client.delete_role(RoleName=role_name)
    except ClientError as err:
        vprint('*'*20 + f" Unable to delete IAM Role {role_name}. Error message:", VERBOSE_LOW)
        vprint(err, VERBOSE_LOW)
        return False
    else:
        return True


############################################################################
# Delete an IAM Policy:
def delete_iam_policy(iam_client, policy_arn):
    vprint(f"Deleting IAM Policy {policy_arn} ...", VERBOSE_MEDIUM)
    try:    
        response = iam_client.get_policy(PolicyArn=policy_arn)
    except ClientError as err:
        vprint('*'*20 + f" IAM Policy {policy_arn} Not Found! Error message:", VERBOSE_MEDIUM)
        vprint(err, VERBOSE_MEDIUM)
        return False
    else:
        vprint(response, VERBOSE_HIGH)

    try:    
        iam_client.delete_policy(PolicyArn=policy_arn)
    except ClientError as err:
        vprint('*'*20 + f" Unable to delete IAM Policy {policy_arn}. Error message:", VERBOSE_LOW)
        vprint(err, VERBOSE_LOW)
        return False
    else:
        return True


def delete_log_groups_with_prefix(cloudwatch_client, prefix):
    vprint(f"Deleting Log Groups with the prefix {prefix} ...", VERBOSE_MEDIUM)
    
    next_token = ''
    response = {}
    # The describe_log_groups() function returns a maximum of 50 log groups.
    # We need a loop to get the whole list
    while True:
        if next_token: # This is NOT the first iteration of the loop
            response = cloudwatch_client.describe_log_groups(
                logGroupNamePrefix = prefix,
                limit = 50,
                includeLinkedAccounts = False,
                nextToken = next_token
            )
        else: # This is the first iteration of the loop
            response = cloudwatch_client.describe_log_groups(
                logGroupNamePrefix = prefix,
                limit = 50,
                includeLinkedAccounts = False,
            )

        if response['logGroups']:
            for log_group in response['logGroups']:
                vprint(f"\tDeleting Log Group '{log_group['logGroupName']}'", VERBOSE_LOW)
                cloudwatch_client.delete_log_group(logGroupName = log_group['logGroupName'])
            if 'nextToken' in response.keys():
                next_token = response['nextToken']
                vprint(f"*********** Next Token for describe_log_groups(): '{next_token}'.", VERBOSE_MEDIUM)
            else:
                break # while True
        else:
            break # while True


############################################################################
#                         Start of the Script
############################################################################
# Basic Checks:
if lza_network_account_id not in lza_non_root_accounts:
    vprint(f"Network account ID '{lza_network_account_id}' not found in the provided list of accounts!\nPlease check the value of the lza_network_account_id parameter in the parameters section of this script.\nAborting.", VERBOSE_LOW)
    exit(1)

if lza_security_account_id not in lza_non_root_accounts:
    vprint(f"Security account ID '{lza_security_account_id}' not found in the provided list of accounts!\nPlease check the value of the lza_security_account_id parameter in the parameters section of this script.\nAborting.", VERBOSE_LOW)
    exit(1)

if lza_operations_account_id not in lza_non_root_accounts:
    vprint(f"Operations account ID '{lza_operations_account_id}' not found in the provided list of accounts!\nPlease check the value of the lza_operations_account_id parameter in the parameters section of this script.\nAborting.", VERBOSE_LOW)
    exit(1)

# Build the list of all accounts:
all_lza_accounts = [(account_id, account_name) for account_id, account_name in lza_non_root_accounts.items()]
all_lza_accounts.append((root_account, root_profile))
vprint("All LZA Accounts:", VERBOSE_MEDIUM)
vprint(all_lza_accounts, VERBOSE_MEDIUM)

# Build the list of connections to all accounts in all regions:
aws_sessions = {}

aws_sessions[(root_account, 'us-east-1')] = boto3.session.Session(profile_name = root_profile, region_name = 'us-east-1')

for region in regions:    
    for account_id, account_name in all_lza_accounts:
        aws_sessions[(account_id, region)] = boto3.session.Session(profile_name=account_name, region_name=region)


############################################################################
#                 Step 1: Delete the LZA SCPs
############################################################################
vprint('\n' + '>'*10 + " Step 1: Delete the LZA SCPs ", VERBOSE_LOW)

organizations = boto3.client('organizations')
response = organizations.list_policies(Filter='SERVICE_CONTROL_POLICY')

lza_scp_found = False
for policy in response['Policies']:
    # Delete all policies whose name starts with the LZA prefix:
    if policy['Name'].startswith(lza_scp_name_prefix):
        detach_and_delete_scp(
            organizations_client = organizations, 
            policy_id = policy['Id'], 
            policy_name = policy['Name']
        )
        lza_scp_found = True

if not lza_scp_found:
    vprint("There are no LZA SCPs to delete!", VERBOSE_LOW)

############################################################################
#          Step 2: Delete the IPAM on the Network Account
############################################################################
vprint('\n' + '>'*10 + " Step 2: Delete the IPAM on the Network Account ", VERBOSE_LOW)

for region in regions:
    # aws_session = boto3.session.Session(profile_name = lza_non_root_accounts[lza_network_account_id], region_name = region)
    ec2 = aws_sessions[(lza_network_account_id, region)].client('ec2')
        
    response = ec2.describe_ipams(
        Filters = [
            {
                'Name': "tag:Name",
                'Values': [lza_ipam_tag_name]
            }
        ]
    )

    for ipam in response['Ipams']:
        vprint(f"Deleting IPAM {ipam['IpamId']} in region {region} ...", VERBOSE_LOW)
        delete_status = ec2.delete_ipam(
            DryRun = False,
            IpamId = ipam['IpamId'],
            Cascade = True
        )

############################################################################
#           Step 3: Clean the 'Security' Account
############################################################################
for region in regions:
    vprint('\n' + '>'*10 + f" Step 3: Clean the 'Security' Account in region '{region}' ", VERBOSE_LOW)

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

    if response['Parameters']:
        for parameter in response['Parameters']:
            vprint(f"Deleting parameter '{parameter['Name']}'", VERBOSE_LOW)
            ssm.delete_parameter(Name = parameter['Name'])
    else:
        vprint(f"There are no SSM parameters to delete!", VERBOSE_LOW)

############################################################################
#                 Step 4: Clean the Operations Account
# - Unshare and Delete the Directories
# - Delete the LZA Managed Active Directory secrets
############################################################################
vprint('\n' + '>'*10 + " Step 4: Clean the Operations Account ", VERBOSE_LOW)

account_name = lza_non_root_accounts[lza_operations_account_id]

for region in regions:
    # aws_session = boto3.session.Session(profile_name = account_name, region_name = region)
    #########################################
    # Unshare and Delete the Directories
    directory_service = aws_sessions[(lza_operations_account_id, region)].client('ds')
    
    response = directory_service.describe_directories()

    for directory in response['DirectoryDescriptions']:
        vprint('-' * 40, VERBOSE_HIGH)
        vprint(directory, VERBOSE_HIGH)
        if directory['Name'] == lza_directory_name:
            vprint(f"------- {directory['DirectoryId']}", VERBOSE_MEDIUM)
            sharing_response = directory_service.describe_shared_directories(OwnerDirectoryId = directory['DirectoryId'])
            
            nb_shared_directories = len(sharing_response['SharedDirectories'])
            for shared_directory in sharing_response['SharedDirectories']:
                vprint(f"\t\tUnsharing shared directory: {shared_directory['SharedDirectoryId']}", VERBOSE_LOW)
                vprint(shared_directory, VERBOSE_HIGH)
                
                unshare_response = directory_service.unshare_directory(
                    DirectoryId = shared_directory['OwnerDirectoryId'],
                    UnshareTarget={
                        'Id': shared_directory['SharedAccountId'],
                        'Type': 'ACCOUNT'
                    }
                )
            
            if nb_shared_directories:
                WAIT_SECONDS = 3
                # Wait WAIT_SECONDS seconds for each unshare operation.
                timer = WAIT_SECONDS * nb_shared_directories
                vprint(f"... Waiting {timer} seconds for the unshare operations to complete ({WAIT_SECONDS} seconds per shared directory, {nb_shared_directories} shared directories) ...", VERBOSE_LOW)
                sleep(timer)

            vprint(f"Deleting Directory {directory['DirectoryId']} ...", VERBOSE_LOW)
            status = directory_service.delete_directory(DirectoryId = directory['DirectoryId'])


    ##########################################
    # Delete the LZA Managed Active Directory secrets

    secrets_manager = aws_sessions[(lza_operations_account_id, region)].client('secretsmanager')
    response = secrets_manager.list_secrets(
        Filters=[
            {
                'Key': 'name',
                'Values': ['/accelerator']
            },
        ],
    )

    if response['SecretList']:
        vprint(f"Deleting LZA Managed Active Directory secrets in the Operations Account '{account_name}'", VERBOSE_LOW)
        for secret in response['SecretList']:
            secrets_manager.delete_secret(
                SecretId = secret['ARN'],
                ForceDeleteWithoutRecovery = True
            )
    else:
        vprint("No secrets to delete for the LZA Managed Active Directory!", VERBOSE_LOW)

############################################################################
#                        Step 5 (for each account):
############################################################################

for region in regions:
    # For each account:
    for account_id, account_name in all_lza_accounts:
        vprint('\n' + '='*80 + '\n' + ' '*5 + f"Cleaning Account {account_name} ({account_id}) in region {region}\n" + '='*80, VERBOSE_LOW)
        
        ############################################################################
        #    Step 5a: Delete the 'AWSAccelerator-SessionManagerEC2Role' IAM role
        ############################################################################
        vprint('\n' + '>'*10 + " Step 5a: Delete the 'AWSAccelerator-SessionManagerEC2Role' IAM role ", VERBOSE_LOW)

        iam = aws_sessions[(account_id, region)].client('iam')
        role_name = f"{lza_session_manager_ec2_role}-{region}"
        
        role_deleted = delete_iam_role(
            iam_client = iam,
            role_name = role_name
        )

        if role_deleted:
            vprint(f"IAM Role {role_name} deleted.", VERBOSE_LOW)
        else:
            vprint(f"There is no IAM Role {role_name} to delete!", VERBOSE_LOW)

        ############################################################################
        #                 Step 5b: Delete the AWSAccelerator-xxxxx Stacks
        ############################################################################
        vprint('\n' + '>'*10 + " Step 5b: Delete the LZA core stacks (AWSAccelerator-xxxxx) ", VERBOSE_LOW)

        cloudformation = aws_sessions[(account_id, region)].client('cloudformation')
        delete_waiter = cloudformation.get_waiter('stack_delete_complete')
        
        stacks_to_delete = []
        stacks_deleted = False
        this_stack_deleted = False
        stack_to_wait = None
        for stack in lza_core_stacks:
            stack_name = f"{stack}-{account_id}-{region}"
            stacks_to_delete.append(stack_name)

            this_stack_deleted = delete_stack(
                cloudformation_client = cloudformation,
                stack_name = stack_name,
                wait_till_deleted = False
            )
            stacks_deleted = stacks_deleted or this_stack_deleted
            stack_to_wait = stack_name
        
        if stacks_deleted:
            while stack_to_wait:
                vprint(f"... Waiting for stack {stack_to_wait} to finish deleting ...", VERBOSE_LOW)
                delete_waiter.wait(StackName = stack_to_wait)
                vprint(f"\tStack {stack_to_wait} completed deletion ...", VERBOSE_LOW)

                # Check if there are other stack still being deleted
                stack_to_wait = None
                response = cloudformation.list_stacks(StackStatusFilter=['DELETE_IN_PROGRESS']) 
                for stack in response['StackSummaries']:
                    stack_name = stack['StackName']
                    if stack_name in stacks_to_delete:
                        stack_to_wait = stack_name
                        break
            
            vprint(f">>> All LZA core stacks in account '{account_name}' were deleted ...", VERBOSE_LOW)

        else:
            vprint(f"There are no LZA core stacks to delete in account '{account_name}'!", VERBOSE_LOW)

        ############################################################################
        #         Step 5c: Delete the StackSet-AWSControlTower...... Stacks
        ############################################################################
        vprint('\n' + '>'*10 + " Step 5c: Delete the StackSet-AWSControlTower...... Stacks ", VERBOSE_LOW)

        stacks_to_delete = []
        stacks_deleted = False
        this_stack_deleted = False
        stack_to_wait = None
        response = cloudformation.list_stacks(StackStatusFilter=['CREATE_COMPLETE', 'UPDATE_COMPLETE', 'DELETE_FAILED']) 
        for stack in response['StackSummaries']:
            stack_name = stack['StackName']
            if stack_name.startswith('StackSet-AWSControlTower'):
                stacks_to_delete.append(stack_name)
                this_stack_deleted = delete_stack(
                    cloudformation_client=cloudformation,
                    stack_name=stack_name,
                    wait_till_deleted=False,
                )
            stacks_deleted = stacks_deleted or this_stack_deleted
            stack_to_wait = stack_name

        if stacks_deleted:
            while stack_to_wait:
                vprint(f"... Waiting for stack {stack_to_wait} to finish deleting (stack_to_wait = {stack_to_wait}) ...", VERBOSE_LOW)
                delete_waiter.wait(StackName = stack_to_wait)
                vprint(f"\tStack {stack_to_wait} completed deletion ...", VERBOSE_LOW)

                # Check if there are other stack still being deleted
                stack_to_wait = None
                response = cloudformation.list_stacks(StackStatusFilter=['DELETE_IN_PROGRESS']) 
                for stack in response['StackSummaries']:
                    stack_name = stack['StackName']
                    if stack_name in stacks_to_delete:
                        stack_to_wait = stack_name
                        break
            
            vprint(f">>> StackSet-AWSControlTower...... Stacks were deleted ...", VERBOSE_LOW)
        else:
            vprint(f"There are no StackSet-AWSControlTower...... Stacks to delete in account '{account_name}'!", VERBOSE_LOW)

        ############################################################################
        #           Step 5d: Delete the LZA S3 Buckets
        ############################################################################
        vprint('\n' + '>'*10 + f" Step 5d: Delete the LZA S3 Buckets in account '{account_name}'", VERBOSE_LOW)
        
        buckets_to_delete = [f"{bucket}-{account_id}-{region}" for bucket in lza_buckets]
        # buckets_to_delete += [f"cdk-accel-assets-{account_id}-{region}"]
        buckets_deleted = False

        s3_resource = aws_sessions[(account_id, region)].resource('s3')
        for bucket_name in buckets_to_delete:
            delete_status = delete_bucket(s3_resource = s3_resource, bucket_name = bucket_name)
            buckets_deleted = buckets_deleted or delete_status
        
        if not buckets_deleted:
            vprint("No buckets deleted!", VERBOSE_LOW)

        ############################################################################
        #           Step 5e: Delete the LZA KMS keys
        ############################################################################
        vprint('\n' + '>'*10 + f" Step 5e: Delete the LZA KMS keys in account '{account_name}'", VERBOSE_LOW)

        kms = aws_sessions[(account_id, region)].client('kms')

        delete_keys_by_tag(kms_client = kms, target_tag_name = lza_tag_name, target_tag_value = lza_tag_value)

        ############################################################################
        #                Step 5f: Delete Log Groups
        ############################################################################
        vprint('\n' + '>'*10 + f" Step 5f: Delete Log Groups in account {account_name} in region '{region}' ", VERBOSE_LOW)
        
        cloudwatch_client = aws_sessions[(account_id, region)].client('logs')

        for prefix in lza_log_groups_prefixes:
            delete_log_groups_with_prefix(cloudwatch_client, prefix)
        
# Separator (End of core accounts cleaning)
vprint('\n' + '='*80, VERBOSE_LOW)

############################################################################
#           Step 6: Delete the Root Account-specific stacks
############################################################################
vprint('\n' + '>'*10 + f" Step 6: Delete the Root Account-specific stacks ", VERBOSE_LOW)

account_id = root_account
stacks_deleted = False
this_stack_deleted = False

###########################################
# Delete the root account stacks in regions
for region in regions:
    cloudformation = aws_sessions[(account_id, region)].client('cloudformation')
    delete_waiter = cloudformation.get_waiter('stack_delete_complete')
    stacks_deleted = False
    this_stack_deleted = False

    for stack in lza_core_stacks + lza_root_stacks_in_region:
        stack_name = f"{stack}-{account_id}-{region}"

        this_stack_deleted = delete_stack(
            cloudformation_client = cloudformation,
            stack_name = stack_name,
            wait_till_deleted = True,
            waiter = delete_waiter
        )
        stacks_deleted = stacks_deleted or this_stack_deleted

    # Delete the LZA Installer Stack
    stack_name = lza_installer_stack

    this_stack_deleted = delete_stack(
        cloudformation_client = cloudformation,
        stack_name = stack_name,
        wait_till_deleted = True,
        waiter = delete_waiter
    )
    stacks_deleted = stacks_deleted or this_stack_deleted

    if not stacks_deleted:
        vprint(f"There are no root account-specific stacks to delete in region {region}")

###########################################
#  Delete the root account stacks specific to 'us-east-1'
region = 'us-east-1'
cloudformation = aws_sessions[(account_id, region)].client('cloudformation')
delete_waiter = cloudformation.get_waiter('stack_delete_complete')
stacks_deleted = False
this_stack_deleted = False

for stack in lza_root_stacks_in_us_east_1:
    stack_name = f"{stack}-{account_id}-{region}"

    this_stack_deleted = delete_stack(
        cloudformation_client = cloudformation,
        stack_name = stack_name,
        wait_till_deleted = True,
        waiter = delete_waiter
    )
    stacks_deleted = stacks_deleted or this_stack_deleted
    stack_to_wait = stack_name

if not stacks_deleted:
    vprint(f"There are no root account-specific stacks to delete in region {region}")

############################################################################
#           Step 7: Delete the Root-specific LZA S3 Buckets
############################################################################
vprint('\n' + '>'*10 + f" Step 7: Delete the Root-specific LZA S3 Buckets ", VERBOSE_LOW)

buckets_to_delete = []
if 'us-east-1' in regions:
    extended_regions = regions
else:
    extended_regions = regions + ['us-east-1']
    
for region in extended_regions:
    buckets_to_delete += [f"aws-accelerator-{bucket}-{account_id}-{region}" for bucket in lza_root_buckets]
    # buckets_to_delete += [f"cdk-accel-assets-{account_id}-{region}"]

buckets_deleted = False

s3_resource = aws_sessions[(root_account, 'us-east-1')].resource('s3')
for bucket_name in buckets_to_delete:
    delete_status = delete_bucket(s3_resource = s3_resource, bucket_name = bucket_name)
    buckets_deleted = buckets_deleted or delete_status

if not buckets_deleted:
    vprint("No buckets deleted!", VERBOSE_LOW)

############################################################################
#      Step 8: Delete the Cost and Usage Report Definition
############################################################################
vprint('\n' + '>'*10 + f" Step 8: Delete the Cost and Usage Report Definition", VERBOSE_LOW)

cost_usage = aws_sessions[(root_account, 'us-east-1')].client('cur')

try:
    vprint(f"Deleting Cost and Usage Report {lza_cost_usage_report_name} ...", VERBOSE_MEDIUM)
    cost_usage.delete_report_definition(
        ReportName = lza_cost_usage_report_name
    )
except ClientError as err:
    vprint(f"\tCost and Usage Report {lza_cost_usage_report_name} Not Found!", VERBOSE_MEDIUM)
    vprint('*'*20 + f"Error message:", VERBOSE_HIGH)
    vprint(err, VERBOSE_HIGH)


############################################################################
#           Step 9: Delete the IAM Policy 'Default-Boundary-Policy'
############################################################################
vprint('\n' + '>'*10 + f" Step 9: Delete the IAM Policy 'Default-Boundary-Policy' ", VERBOSE_LOW)

region = 'us-east-1'
iam = aws_sessions[(root_account, region)].client('iam')

policy_arn = f"arn:aws:iam::{root_account}:policy/Default-Boundary-Policy"

policy_deleted = delete_iam_policy(
    iam_client = iam,
    policy_arn = policy_arn
)

if policy_deleted:
    vprint(f"IAM Policy {policy_arn} deleted.", VERBOSE_LOW)
else:
    vprint(f"There is no IAM Policy {policy_arn} to delete!", VERBOSE_LOW)

############################################################################
#                Step 10: Rename the CodeCommit Repo
############################################################################
for region in regions:
    vprint('\n' + '>'*10 + f" Step 10: Rename the CodeCommit Repo in region '{region}' ", VERBOSE_LOW)

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

############################################################################
#                Step 11: Remove service delegations
############################################################################
vprint('\n' + '>'*10 + f" Step 11: Remove service delegations", VERBOSE_LOW)
delegations_found = False

for region in regions:
    for account_id, account_name in all_lza_accounts:
        vprint(f"Remove service delegations in account {account_name} in region '{region}' ", VERBOSE_MEDIUM)

        organizations = aws_sessions[(root_account, region)].client('organizations')
        
        try:
            response = organizations.list_delegated_services_for_account(AccountId = account_id)
        except ClientError as err:
            vprint(f"\tNo delegated services in Account {account_name}", VERBOSE_MEDIUM)
        else:
            delegations_found = True
            for delegated_service in response['DelegatedServices']:
                service = delegated_service['ServicePrincipal']
                
                vprint(f"Removing service delegation for account {account_name} on service {service}", VERBOSE_LOW)
                organizations.deregister_delegated_administrator(
                    AccountId = account_id,
                    ServicePrincipal = service
                )

if not delegations_found:
    vprint(f"No service delegations found!", VERBOSE_LOW)

############################################################################
#                Step 12: Disable Security services
############################################################################
vprint('\n' + '>'*10 + f" Step 12: Disable Security services", VERBOSE_LOW)

for region in regions:
    for account_id, account_name in all_lza_accounts:
        print('-'*30 + f"Region '{region}' --- Account '{account_name}' ({account_id})")

        ###### Disabling GuardDuty
        vprint(f"Disabling the GuardDuty service", VERBOSE_LOW)
        guardduty = aws_sessions[(account_id, region)].client('guardduty')
        response = guardduty.list_detectors()
        for detector_id in response['DetectorIds']:
            vprint(f"\tDeleting detector ID '{detector_id}' ...", VERBOSE_MEDIUM)
            status = guardduty.delete_detector(
                DetectorId=detector_id
            )


        ###### Disabling Macie
        vprint(f"Disabling the Macie service", VERBOSE_LOW)
        macie = aws_sessions[(account_id, region)].client('macie2')
        try:
            response = macie.disable_macie()
        except ClientError as err:
            vprint('*'*20 + f" Unable to disable Macie! Error message:", VERBOSE_MEDIUM)
            vprint(err, VERBOSE_MEDIUM)
        else:
            vprint(f"\t\tAWS Macie service disabled.", VERBOSE_LOW)
            vprint(response, VERBOSE_HIGH)


        ###### Disabling SecurityHub
        vprint(f"Disabling the SecurityHub service", VERBOSE_LOW)
        securityhub = aws_sessions[(account_id, region)].client('securityhub')
        try:
            response = securityhub.disable_security_hub()
        except ClientError as err:
            vprint('*'*20 + f" Unable to disable SEcurityHub! Error message:", VERBOSE_MEDIUM)
            vprint(err, VERBOSE_MEDIUM)
        else:
            vprint(f"\t\tAWS SecurityHub service disabled.", VERBOSE_LOW)
            vprint(response, VERBOSE_HIGH)


vprint(f"\nWaiting 30 seconds for the services to finish disabling ...\n", VERBOSE_LOW)
sleep(30)


###### Delete Service Linked Roles
vprint(f"\nDeleting Service Linked Roles", VERBOSE_LOW)
for region in regions:
    for account_id, account_name in all_lza_accounts:
        vprint(f"\tDeleting service-linked roles in account {account_name} in region '{region}' ", VERBOSE_LOW)
        iam = aws_sessions[(account_id, region)].client('iam')

        for role in lza_service_linked_roles:
            vprint(f"\t----- Deleting {role}", VERBOSE_MEDIUM)
            
            try:    
                response = iam.delete_service_linked_role(RoleName=role)
            except ClientError as err:
                vprint('*'*20 + f" IAM Role {role} Not Found! Error message:", VERBOSE_MEDIUM)
                vprint(err, VERBOSE_MEDIUM)
            else:
                vprint(f"\t\tIAM role {role} deleted.", VERBOSE_LOW)
                vprint(response, VERBOSE_HIGH)




############################################################################
#                Step 13: ControlTower Clean-up
############################################################################
# Refer to: https://docs.aws.amazon.com/en_us/controltower/latest/userguide//known-issues-decommissioning.html
vprint('\n' + '>'*10 + f" Step 13: ControlTower Clean-up", VERBOSE_LOW)

for region in regions:
    for account_id, account_name in all_lza_accounts:
        vprint(f"ControlTower Clean-up in account {account_name} in region '{region}' ", VERBOSE_LOW)

        ###### Delete ControlTower Roles
        vprint(f"\tDeleting ControlTower Roles", VERBOSE_LOW)
        iam = aws_sessions[(account_id, region)].client('iam')
        for role_name in control_tower_roles:
            role_deleted = delete_iam_role(
                iam_client = iam,
                role_name = role_name
            )

            if role_deleted:
                vprint(f"IAM Role {role_name} deleted.", VERBOSE_LOW)
            else:
                vprint(f"There is no IAM Role {role_name} to delete!", VERBOSE_MEDIUM)

        ###### Delete ControlTower IAM policies
        vprint(f"\tDeleting ControlTower IAM policies", VERBOSE_LOW)
        iam = aws_sessions[(account_id, region)].client('iam')
        for policy in control_tower_policies:
            policy_arn = f"arn:aws:iam::{root_account}:policy/{policy}"

            policy_deleted = delete_iam_policy(
                iam_client = iam,
                policy_arn = policy_arn
            )

            if policy_deleted:
                vprint(f"IAM Policy {policy_arn} deleted.", VERBOSE_LOW)
            else:
                vprint(f"There is no IAM Policy {policy_arn} to delete!", VERBOSE_MEDIUM)


        ###### Delete ControlTower S3 buckets
        vprint(f"\tDeleting ControlTower S3 buckets", VERBOSE_LOW)
        s3_resource = aws_sessions[(account_id, region)].resource('s3')
        buckets_to_delete = [f"{bucket}-{account_id}-{region}" for bucket in control_tower_buckets]
        buckets_deleted = False

        for bucket_name in buckets_to_delete:
            delete_status = delete_bucket(s3_resource = s3_resource, bucket_name = bucket_name)
            buckets_deleted = buckets_deleted or delete_status
        
        if not buckets_deleted:
            vprint("No buckets deleted!", VERBOSE_LOW)

        ###### Delete ControlTower Log Groups
        vprint(f"\tDeleting ControlTower Log Groups", VERBOSE_LOW)
        cloudwatch_client = aws_sessions[(account_id, region)].client('logs')

        for prefix in control_tower_log_groups_prefixes:
            delete_log_groups_with_prefix(cloudwatch_client, prefix)
        

        ###### Disabling ControlTower Service Principal in AWS Organizations
        vprint(f"\tDisabling ControlTower Service Principal in AWS Organizations", VERBOSE_LOW)
        organizations = boto3.client('organizations')
        response = organizations.disable_aws_service_access(
            ServicePrincipal=control_tower_service_principal
        )
        

        ###### Delete ControlTower Events rules
        vprint(f"\tDeleting ControlTower Events rules", VERBOSE_LOW)
        event_bridge_client = aws_sessions[(account_id, region)].client('events')
        for rule_name in control_tower_events_rules:
            try:
                response = event_bridge_client.delete_rule(
                    Name=rule_name,
                    Force=True
                )
            except ClientError as err:
                vprint('*'*20 + f" EventBridge rule {rule_name} Not Found! Error message:", VERBOSE_MEDIUM)
                vprint(err, VERBOSE_MEDIUM)
            else:
                vprint(f"\t\tEventBridge rule {rule_name} deleted.", VERBOSE_LOW)
                vprint(response, VERBOSE_HIGH)
                


############################################################################
#                                   THE END
############################################################################

vprint(f"\nAWS LZA Wipe-Out Ended", VERBOSE_LOW)
