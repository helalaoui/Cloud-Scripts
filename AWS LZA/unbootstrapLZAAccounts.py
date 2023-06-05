############################################################################
#          Wipe-Out Script of the AWS Landing Zone Accelerator (LZA)
#
#    ******************   USE AT YOUR OWN RISK !!! *****************
#
# Script steps:
#       1: For each account:
#          1a: Delete the AWSAccelerator-CDKToolkit stack
#          1b: Delete the LZA S3 Buckets
#          1c: Delete the LZA ECR Repository (CDK)
#       2: Delete the Root-specific LZA S3 Buckets
#
#  Please fill-in the Parameters section before running this script.
#
#  The context for execution of this script should already have a valid
#    AWS authentication context: .aws/credentials and .aws/config
#
#  Version 1.5 - 2023-06-05
#  Author: Hicham El Alaoui - alaoui@it-pro.com
#
############################################################################

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
    "22222222222": "Network",
    "33333333333": "Operations"
}

# The network account that needs to be cleaned in step 1b:
lza_network_account_id = "22222222222"

# The operations account that needs to be cleaned in step 1c:
lza_operations_account_id = "33333333333"

# The security account that needs to be cleaned in step 5:
lza_security_account_id = "11111111111"

# Message verbose level you want. Options: VERBOSE_NONE, VERBOSE_LOW, VERBOSE_MEDIUM,
#    or VERBOSE_HIGH. Recommended: VERBOSE_LOW.
requested_verbose_level = VERBOSE_LOW

############################################################################
#                            LZA Internal Parameters
############################################################################

lza_cdk_stack = 'AWSAccelerator-CDKToolkit'

lza_cdk_bucket = 'cdk-accel-assets'

lza_cdk_repo = 'cdk-accel-container-assets'

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
#                         Start of the Script
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

    # for account_id, account_name in lza_non_root_accounts.items():
    for account_id, account_name in all_lza_accounts:
        vprint('\n' + '='*80 + '\n' + ' '*5 + f"Cleaning Account {account_name} ({account_id}) in region {region}\n" + '='*80, VERBOSE_LOW)
        
        ############################################################################
        #           Step 1a: Delete the AWSAccelerator-CDKToolkit stack
        ############################################################################
        vprint('\n' + '>'*10 + f" Step 2c: Delete the AWSAccelerator-CDKToolkit stack in account '{account_name}'", VERBOSE_LOW)
        stack_name = lza_cdk_stack

        cloudformation = aws_sessions[(account_id, region)].client('cloudformation')
        delete_waiter = cloudformation.get_waiter('stack_delete_complete')

        this_stack_deleted = delete_stack(
            cloudformation_client = cloudformation,
            stack_name = stack_name,
            wait_till_deleted = True,
            waiter = delete_waiter
        )
    
        if not this_stack_deleted:
            vprint(f"There is no {stack_name} stack to delete!")

        ############################################################################
        #           Step 1b: Delete the LZA S3 Buckets
        ############################################################################
        vprint('\n' + '>'*10 + f" Step 2d: Delete the LZA S3 Buckets in account '{account_name}'", VERBOSE_LOW)
        
        bucket_to_delete = f"{lza_cdk_bucket}-{account_id}-{region}"

        s3_resource = aws_sessions[(account_id, region)].resource('s3')
        bucket_deleted = delete_bucket(s3_resource = s3_resource, bucket_name = bucket_to_delete)
        
        if bucket_deleted:
            vprint(f"\tCDK Bucket {bucket_to_delete} deleted in Account {account_name}.", VERBOSE_LOW)

        ############################################################################
        #           Step 1c: Delete the LZA ECR Repository (CDK)
        ############################################################################
        vprint('\n' + '>'*10 + f" Step 2e: Delete the LZA ECR Repository (CDK) in account '{account_name}'", VERBOSE_LOW)

        ecr = aws_sessions[(account_id, region)].client('ecr')
        cdk_repo = f"{lza_cdk_repo}-{account_id}-{region}"
        
        repo_deleted = delete_ecr_repo(ecr_client = ecr, repo_name = cdk_repo)
        if not repo_deleted:
            vprint(f"There is no LZA ECR Repository (CDK)!", VERBOSE_LOW)
        

############################################################################
#           Step 2: Delete the Root-specific LZA S3 Buckets
############################################################################
vprint('\n' + '>'*10 + f" Step 5: Delete the Root-specific LZA S3 Buckets ", VERBOSE_LOW)

buckets_to_delete = []
if 'us-east-1' in regions:
    extended_regions = regions
else:
    extended_regions = regions + ['us-east-1']
    
for region in extended_regions:
    buckets_to_delete += [f"{lza_cdk_bucket}-{root_account}-{region}"]

buckets_deleted = False

s3_resource = aws_sessions[(root_account, 'us-east-1')].resource('s3')
for bucket_name in buckets_to_delete:
    delete_status = delete_bucket(s3_resource = s3_resource, bucket_name = bucket_name)
    buckets_deleted = buckets_deleted or delete_status

if not buckets_deleted:
    vprint("No buckets deleted!", VERBOSE_LOW)



vprint(f"\nAWS LZA Wipe-Out Ended", VERBOSE_LOW)

