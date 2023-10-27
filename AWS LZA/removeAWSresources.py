from datetime import datetime
from time import sleep
import logging
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

def test1():
    print("=== Module ===")

    logger.debug('Module Debug')
    logger.info('Module Info')


############################################################################
# Delete a CloudFormation Stack
def delete_stack(cloudformation_client, stack_name, wait_till_deleted=False, waiter=None):
    logger.info(f"Deleting the {stack_name} stack ...")
    # Check if the stack exists and is in a COMPLETE state:
    try:
        stack_response = cloudformation_client.describe_stacks(StackName = stack_name)
    except ClientError as err:
        logger.debug(f"\tStack Not Found: {stack_name}.")
        logger.debug('*'*20 + f"Error message:")
        logger.debug("*"*10 + str(err))
        return False

    stack_status = stack_response['Stacks'][0]['StackStatus']
    if stack_status not in ['CREATE_COMPLETE', 'UPDATE_COMPLETE', 'DELETE_FAILED']:
        logger.info(f"\tStack {stack_name} has a status of '{stack_status}' which is not CREATE_COMPLETE nor UPDATE_COMPLETE. Skipping ...")
        return False
    
    try:
        logger.debug(f"\tDisabling Termination Protection on stack {stack_name}")
        response = cloudformation_client.update_termination_protection(EnableTerminationProtection=False, StackName=stack_name)
        logger.debug(response)

        logger.info(f"Starting Deletion of the {stack_name} stack")
        cloudformation_client.delete_stack(StackName=stack_name)

        if wait_till_deleted:
            logger.info(f"\tWaiting for stack {stack_name} to finish deleting ...")
            waiter.wait(StackName=stack_name)
            logger.info(f"\tStack {stack_name} deleted ...")
        return True
    except ClientError as err:
        logger.info(f"\tUnable to delete Stack {stack_name}!")
        logger.info('*'*20 + f"Error message:")
        logger.info("*"*10 + str(err))
        return False

############################################################################
# Empty and delete a Bucket:
# Returns True if bucket deleted or False otherwise.
def delete_bucket(s3_resource, bucket_name):
    try:
        logger.debug(f"\tDeleting all objects in bucket {bucket_name}")
        bucket_versioning = s3_resource.BucketVersioning(bucket_name)
        versioning_status = bucket_versioning.status
    except ClientError as err:
        logger.debug('*'*20 + f" Bucket Not Found! Error message:")
        logger.debug("*"*10 + str(err))
        return False

    try:
        bucket = s3_resource.Bucket(bucket_name)
        if versioning_status == 'Enabled':
            bucket.object_versions.delete()
        else:
            bucket.objects.all().delete()
        logger.info(f"Deleting bucket {bucket_name} ...")
        bucket.delete()
    except ClientError as err:
        logger.info('*'*20 + f" Unable to delete bucket {bucket_name}. Error message:")
        logger.info("*"*10 + str(err))
        return False
    else:
        return True
    
############################################################################
# Delete an ECR repository:
def delete_ecr_repo(ecr_client, repo_name):
    logger.debug(f"Deleting ECR Repository {repo_name} ...")
    try:    
        response = ecr_client.describe_repositories(repositoryNames = [repo_name])
    except ClientError as err:
        logger.debug('*'*20 + f" ECR Repository {repo_name} Not Found! Error message:")
        logger.debug("*"*10 + str(err))
        return False

    try:    
        ecr_client.delete_repository(repositoryName=repo_name, force=True)
            
    except ClientError as err:
        logger.info('*'*20 + f" Unable to delete ECR repository {repo_name}. Error message:")
        logger.info("*"*10 + str(err))
        return False
    else:
        return True

############################################################################
# Delete all KMS keys having a given tag:
def delete_keys_by_tag(kms_client, target_tag_name, target_tag_value):
    logger.debug(f"Deleting all KMS keys with tag {target_tag_name} = '{target_tag_value}'...")
    
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
                    logger.debug(f"\tIgnoring AWS-managed KMS key {key_id} ...")
                    continue

                if key_response['KeyMetadata']['KeyState'] != 'Enabled':
                    logger.debug(f"\tIgnoring KMS key {key_id} (not in 'Enabled' state) ...")
                    continue

                # Get the list of tags of this key:
                tags_response = kms_client.list_resource_tags(KeyId = key_id)
                
                if tags_response['Tags']:
                    # Check if one of the tags matches the target tag
                    for tag in tags_response['Tags']:
                        if tag['TagKey'] == target_tag_name:
                            if tag['TagValue'] == target_tag_value:
                                target_key_found = True
                                logger.info(f"Scheduling deletion of KMS key {key_id} ...")
                                delete_response = kms_client.schedule_key_deletion(KeyId = key_id, PendingWindowInDays=7)
                                logger.info(f"\tDeletion scheduled for '{delete_response['DeletionDate']}' GW.")
                            else:
                                logger.info(f"\tKMS key {key_id} has a '{target_tag_name}' tag but not with the target value. Actual tag value = '{tag['TagValue']}', target tag value = '{target_tag_value}'.Skipping ...")
                        else:
                            logger.debug(f"\tIrrelevant tag {tag['TagKey']}. Skipping  ...")
                
        except ClientError as err:
            logger.info('*'*20 + f" Unable to delete KMS keys. Error message:")
            logger.info("*"*10 + str(err))

        if not target_key_found:
            logger.info(f"There are no tags with name '{target_tag_name}' and value '{target_tag_value}'!")
        
    else:
        logger.info(f"There are no KMS keys in this account.")

    
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
                logger.debug(f"\tDetaching SCP {policy_name} from target {target['Name']} ...")
                organizations_client.detach_policy(PolicyId = policy_id, TargetId = target['TargetId'])
            except ClientError as err:
                logger.info(f"Unable to detach SCP {policy_name} from target {target['Name']}. Error Message:")
                logger.info("*"*10 + str(err))
                policy_is_attached = True
    else:
        policy_is_attached = False
    
    if policy_is_attached:
        logger.info(f"Unable to detach AWS Organizations SCP {policy_name}! Skipping ...")
        return
    
    logger.info(f"Deleting AWS Organizations SCP {policy_name} ...")
    try:
        organizations_client.delete_policy(PolicyId = policy_id)
    except ClientError as err:
        logger.info(f"Unable to delete AWS Organizations SCP {policy_name}. Error Message:")
        logger.info("*"*10 + str(err))

    return

############################################################################
# Delete an IAM Role:
def delete_iam_role(iam_client, role_name):
    logger.debug(f"Deleting IAM Role {role_name} ...")

    # Check if the role exists
    try:    
        response = iam_client.get_role(RoleName=role_name)
    except ClientError as err:
        logger.debug('*'*20 + f" IAM Role {role_name} Not Found! Error message:")
        logger.debug("*"*10 + str(err))
        return False
    else:
        logger.debug(response)

    # Detach all policies from this role:
    try:
        response = iam_client.list_attached_role_policies(RoleName = role_name)
    except ClientError as err:
        logger.debug(f"Role {role_name} not found! Error Message:")
        logger.debug("*"*10 + str(err))
        return False

    policy_is_attached = False
    if response['AttachedPolicies']:
        for policy in response['AttachedPolicies']:
            try:
                logger.debug(f"\tDetaching role {role_name} from policy {policy['PolicyName']} ...")
                iam_client.detach_role_policy(RoleName = role_name, PolicyArn = policy['PolicyArn'])
            except ClientError as err:
                logger.info(f"Unable to detach role {role_name} from policy {policy['PolicyName']}. Error Message:")
                logger.info("*"*10 + str(err))
                policy_is_attached = True
    else:
        policy_is_attached = False
    
    if policy_is_attached:
        logger.info(f"Unable to detach policies from {role_name}! Skipping ...")
        return

    # Wait 2 seconds for the state to propagate
    sleep(2)
    
    # Finally delete the role
    try:    
        iam_client.delete_role(RoleName=role_name)
    except ClientError as err:
        logger.info('*'*20 + f" Unable to delete IAM Role {role_name}. Error message:")
        logger.info("*"*10 + str(err))
        return False
    else:
        return True


############################################################################
# Delete an IAM Policy:
def delete_iam_policy(iam_client, policy_arn):
    logger.debug(f"Deleting IAM Policy {policy_arn} ...")
    try:    
        response = iam_client.get_policy(PolicyArn=policy_arn)
    except ClientError as err:
        logger.debug('*'*20 + f" IAM Policy {policy_arn} Not Found! Error message:")
        logger.debug("*"*10 + str(err))
        return False
    else:
        logger.debug(response)

    try:    
        iam_client.delete_policy(PolicyArn=policy_arn)
    except ClientError as err:
        logger.info('*'*20 + f" Unable to delete IAM Policy {policy_arn}. Error message:")
        logger.info("*"*10 + str(err))
        return False
    else:
        return True


def delete_log_groups_with_prefix(cloudwatch_client, prefix):
    logger.debug(f"Deleting Log Groups with the prefix {prefix} ...")
    
    next_token = None
    response = {}
    # The describe_log_groups() function returns a maximum of 50 log groups.
    # We need a loop to get the whole list
    while True:
        if next_token: # This is NOT the first iteration of the loop
            logger.debug(f"\tGetting 2nd and subsequent pages of the Log Group list with prefix '{prefix}'")
            response = cloudwatch_client.describe_log_groups(
                logGroupNamePrefix = prefix,
                limit = 50,
                includeLinkedAccounts = False,
                nextToken = next_token
            )
            logger.debug(response)
        else: # This is the first iteration of the loop
            logger.debug(f"\tGetting 1st page of the Log Group list with prefix '{prefix}'")
            response = cloudwatch_client.describe_log_groups(
                logGroupNamePrefix = prefix,
                limit = 50,
                includeLinkedAccounts = False,
            )
            logger.debug(response)

        if response['logGroups']:
            for log_group in response['logGroups']:
                logger.info(f"\tDeleting Log Group '{log_group['logGroupName']}'")
                cloudwatch_client.delete_log_group(logGroupName = log_group['logGroupName'])
            if 'nextToken' in response.keys():
                next_token = response['nextToken']
                logger.debug(f"*********** Next Token for describe_log_groups(): '{next_token}'.")
            else:
                break # while True
        else:
            logger.debug(f"\tThere are no Log Groups with prefix '{prefix}'")
            break # while True


def disable_guardduty(aws_session):
    ###### Disabling GuardDuty
    logger.info(f"Disabling the GuardDuty service")
    guardduty = aws_session.client('guardduty')
    response = guardduty.list_detectors()
    for detector_id in response['DetectorIds']:
        members_response = guardduty.list_members(
            DetectorId=detector_id
        )
        print(members_response)
        if members_response['Members']:
            member_list = [member['AccountId'] for member in members_response['Members']]
            logger.info(f"\tDisassociating GuardDuty members: " + str(member_list))
            guardduty.disassociate_members(
                DetectorId=detector_id,
                AccountIds=member_list
            )
        else:
            logger.info(f"\tThere are no GuardDuty members to diassociate!")
        
        logger.info(f"\tDeleting detector ID '{detector_id}' ...")
        status = guardduty.delete_detector(
            DetectorId=detector_id
        )


def disable_macie(aws_session):
    ###### Disabling Macie
    logger.info(f"Disabling the Macie service")
    macie = aws_session.client('macie2')
    try:
        response = macie.disable_macie()
    except ClientError as err:
        logger.debug('*'*20 + f" Unable to disable Macie! Error message:")
        logger.debug("*"*10 + str(err))
    else:
        logger.info(f"\tAWS Macie service disabled.")
        logger.debug(response)


def disable_security_hub(aws_session):
    ###### Disabling SecurityHub
    logger.info(f"Disabling the SecurityHub service")
    securityhub = aws_session.client('securityhub')
    try:
        response = securityhub.disable_security_hub()
    except ClientError as err:
        logger.debug('*'*20 + f" Unable to disable SecurityHub! Error message:")
        logger.debug("*"*10 + str(err))
    else:
        logger.info(f"\tAWS SecurityHub service disabled.")
        logger.debug(response)


