############################################################################
#    Clean the AWS environment after AWS Control Tower is decommissioned
# https://docs.aws.amazon.com/en_us/controltower/latest/userguide//known-issues-decommissioning.html
#
#    ******************   USE AT YOUR OWN RISK !!! *****************
#
#  Please fill-in the Parameters section before running this script.
#
#  The context for execution of this script should already have a valid
#    AWS authentication context: .aws/credentials and .aws/config
#
#  Version 1.0 - 2023-10-10
#  Author: Hicham El Alaoui - alaoui@it-pro.com
#
############################################################################

from time import sleep
import logging
# AWS SDK for Python modules:
import boto3
from botocore.exceptions import ClientError
# My module of functions to delete AWS resources:
import removeAWSresources

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

# Logging level: choose either logging.INFO (recommended) or logging.DEBUG:
requested_verbose_level = logging.INFO

############################################################################
#                      AWS Control Tower Internal Parameters
############################################################################

control_tower_stacksets = [
    "AWSControlTowerExecutionRole",
    "AWSControlTowerLoggingResources",
    "AWSControlTowerSecurityResources",
    "AWSControlTowerBP-BASELINE-CLOUDWATCH",
    "AWSControlTowerBP-BASELINE-CONFIG",
    "AWSControlTowerBP-SECURITY-TOPICS",
    "AWSControlTowerBP-BASELINE-ROLES",
    "AWSControlTowerBP-BASELINE-SERVICE-ROLES",
    "AWSControlTowerBP-BASELINE-SERVICE-LINKED-ROLE",
]

control_tower_roles = [
    "AWSControlTowerAdmin",
    "AWSControlTowerCloudTrailRole",
    "AWSControlTowerStackSetRole",
    "AWSControlTowerConfigAggregatorRoleForOrganizations",
    "aws-controltower-AdministratorExecutionRole",
    "aws-controltower-ForwardSnsNotificationRole",
    "aws-controltower-AuditAdministratorRole",
    "aws-controltower-AuditReadOnlyRole	",
    "aws-controltower-AdministratorExecutionRole",
    "aws-controltower-ReadOnlyExecutionRole",
]

control_tower_service_linked_roles = [
    "AWSServiceRoleForAWSControlTower"
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
#                     Define Some Useful Functions
############################################################################
logger = logging.getLogger(__name__)

def delete_ct_stacks(aws_session):
    cloudformation = aws_session.client('cloudformation')
    delete_waiter = cloudformation.get_waiter('stack_delete_complete')

    stacks_to_delete = []
    stacks_deleted = False
    this_stack_deleted = False
    stack_to_wait = None
    response = cloudformation.list_stacks(StackStatusFilter=['CREATE_COMPLETE', 'UPDATE_COMPLETE', 'DELETE_FAILED']) 
    for stack in response['StackSummaries']:
        stack_name = stack['StackName']
        if stack_name.startswith('StackSet-AWSControlTower'):
            stacks_to_delete.append(stack_name)
            this_stack_deleted = removeAWSresources.delete_stack(
                cloudformation_client=cloudformation,
                stack_name=stack_name,
                wait_till_deleted=False,
            )
        stacks_deleted = stacks_deleted or this_stack_deleted
        stack_to_wait = stack_name

    if stacks_deleted:
        while stack_to_wait:
            logger.info(f"... Waiting for stack {stack_to_wait} to finish deleting ...")
            delete_waiter.wait(StackName = stack_to_wait)
            logger.info(f"\tStack {stack_to_wait} completed deletion ...")

            # Check if there are other stack still being deleted
            stack_to_wait = None
            response = cloudformation.list_stacks(StackStatusFilter=['DELETE_IN_PROGRESS']) 
            for stack in response['StackSummaries']:
                stack_name = stack['StackName']
                if stack_name in stacks_to_delete:
                    stack_to_wait = stack_name
                    break
        
        logger.info(f">>> StackSet-AWSControlTower...... Stacks were deleted ...")
    else:
        logger.info(f"There are no StackSet-AWSControlTower...... Stacks to delete in this account!")

def delete_ct_stacksets(aws_session, accounts, regions):
    cloudformation = aws_session.client('cloudformation')

    current_stacksets = cloudformation.list_stack_sets(Status='ACTIVE')
    logger.debug(current_stacksets)
    
    delete_count = 0
    for stackset in current_stacksets['Summaries']:
        stackset_name = stackset['StackSetName']
        
        if stackset_name in control_tower_stacksets:
            logger.info(f"\tDeleting StackSet {stackset_name} ...")
        else:
            logger.info(f"\tIgnoring StackSet {stackset_name} ...")
            continue

        try:
            cloudformation.delete_stack_instances(
                StackSetName=stackset_name,
                Accounts=accounts,
                Regions=regions,
                RetainStacks=True,
            )
        except ClientError as err:
            logger.debug('*'*20 + f" Stackset {stackset} Not Found! Error message:")
            logger.debug("*"*10 + str(err))
        else:
            delete_count += 1
        
    return delete_count   

def delete_ct_roles(aws_session):
    iam = aws_session.client('iam')
    
    for role_name in control_tower_roles:
        role_deleted = removeAWSresources.delete_iam_role(
            iam_client = iam,
            role_name = role_name
        )

        if role_deleted:
            logger.info(f"IAM Role {role_name} deleted.")
        else:
            logger.debug(f"There is no IAM Role {role_name} to delete!")


def delete_ct_service_linked_roles(aws_session):
    iam = aws_session.client('iam')
    
    for role in control_tower_service_linked_roles:
        logger.debug(f"\t----- Deleting service-linked role '{role}'")
        
        try:    
            response = iam.delete_service_linked_role(RoleName=role)
        except ClientError as err:
            logger.debug('*'*20 + f" IAM service-linked Role {role} Not Found! Error message:")
            logger.debug("*"*10 + str(err))
        else:
            logger.info(f"\t\tIAM service-linked role {role} deleted.")
            logger.debug(response)

def delete_ct_iam_policies(aws_session):
    iam = aws_session.client('iam')
    for policy in control_tower_policies:
        policy_arn = f"arn:aws:iam::{root_account}:policy/service-role/{policy}"

        logger.debug(f"Deleting IAM policy '{policy}' with ARN '{policy_arn}'")
        policy_deleted = removeAWSresources.delete_iam_policy(
            iam_client = iam,
            policy_arn = policy_arn
        )

        if policy_deleted:
            logger.info(f"IAM Policy {policy_arn} deleted.")
        else:
            logger.debug(f"There is no IAM Policy {policy_arn} to delete!")

def delete_ct_buckets(aws_session, bucket_suffix):
    s3_resource = aws_session.resource('s3')
    buckets_to_delete = [f"{bucket}-{bucket_suffix}" for bucket in control_tower_buckets]
    buckets_deleted = False

    for bucket_name in buckets_to_delete:
        delete_status = removeAWSresources.delete_bucket(s3_resource = s3_resource, bucket_name = bucket_name)
        buckets_deleted = buckets_deleted or delete_status
    
    if not buckets_deleted:
        logger.info("No buckets deleted!")

def delete_ct_log_groups(aws_session):
    cloudwatch_client = aws_session.client('logs')

    for prefix in control_tower_log_groups_prefixes:
        removeAWSresources.delete_log_groups_with_prefix(cloudwatch_client, prefix)
        

def delete_ct_event_rules(aws_session):
    event_bridge_client = aws_session.client('events')
    for rule_name in control_tower_events_rules:
        # Check if rule exists

        try:
            response = event_bridge_client.describe_rule(
                Name=rule_name
            )
        except ClientError as err:
            logger.debug('*'*20 + f" EventBridge rule {rule_name} Not Found! Error message:")
            logger.debug("*"*10 + str(err))
            continue
        else:
            logger.debug(f"\t\tEventBridge rule {rule_name} found.")
            logger.debug(response)

        # Get the list of targets for the rule
        try:
            response = event_bridge_client.list_targets_by_rule(
                Rule=rule_name
            )
        except ClientError as err:
            logger.debug('*'*20 + f" EventBridge rule {rule_name} has no targets! Error message:")
            logger.debug("*"*10 + str(err))
            continue
        else:
            logger.debug(f"\t\tEventBridge rule {rule_name} has targets.")
            logger.debug(response)
        
        # Delete the targets
        target_ids = [target['Id'] for target in response['Targets']]
        logger.debug(f"\t\tDeleting targets of rule {rule_name} (IDs: " + str(target_ids) + ")")
        
        response = event_bridge_client.remove_targets(
            Rule=rule_name,
            Ids=target_ids,
            Force=True
        )
        
        # Delete the rule
        try:
            response = event_bridge_client.delete_rule(
                Name=rule_name,
                Force=True
            )
        except ClientError as err:
            logger.debug('*'*20 + f" EventBridge rule {rule_name} Not Found! Error message:")
            logger.debug("*"*10 + str(err))
        else:
            logger.info(f"\t\tEventBridge rule {rule_name} deleted.")
            logger.debug(response)

def disable_ct_principal(aws_session):
    organizations = aws_session.client('organizations')
    response = organizations.disable_aws_service_access(
        ServicePrincipal=control_tower_service_principal
    )
        

def main():
    logging.basicConfig(format='%(message)s')
    logger.setLevel(requested_verbose_level)

    ############################################################################
    #                         Start of the Script
    ############################################################################

    # Build the list of all accounts:
    all_lza_accounts = [(account_id, account_name) for account_id, account_name in lza_non_root_accounts.items()]
    all_lza_accounts.append((root_account, root_profile))
    logger.debug("All LZA Accounts:")
    logger.debug(all_lza_accounts)

    # Extended regions = regions + 'us-east-1'
    extended_regions = regions
    if 'us-east-1' not in regions: extended_regions = regions + ['us-east-1']

    # Build the list of connections to all accounts in all regions:
    aws_sessions = {}
    for region in extended_regions:    
        for account_id, account_name in all_lza_accounts:
            aws_sessions[(account_id, region)] = boto3.session.Session(profile_name=account_name, region_name=region)

    # Start cleaning
    for region in regions:

        ###### Delete the ControlTower Stacks Sets instances
        logger.info(f"Deleting the ControlTower Stacks Sets instances")
        delete_count = delete_ct_stacksets(
            aws_session = aws_sessions[(root_account, region)],
            accounts = [account_id for account_id, account_name in all_lza_accounts],
            regions = regions
        )

        if delete_count:
            logger.info(f"Waiting 30 seconds for the stackset instances to finish deleting ...")
            sleep(30)
        
        ###### For every account:
        for account_id, account_name in all_lza_accounts:
            logger.info('='*80 + f"\n   ControlTower Clean-up in account {account_name} ({account_id}) in region '{region}'\n" + '='*80)

            aws_session = aws_sessions[(account_id, region)]
            
            ###### Delete the StackSet-AWSControlTower...... Stacks
            logger.info(f"\tDeleting the StackSet-AWSControlTower...... Stacks")
            delete_ct_stacks(aws_session)

            ###### Delete ControlTower Roles
            logger.info(f"\tDeleting ControlTower Roles")
            delete_ct_roles(aws_session)

            ###### Delete ControlTower Service-Linked Roles
            logger.info(f"\tDeleting ControlTower Service-Linked Roles")
            delete_ct_service_linked_roles(aws_session)
            
            ###### Delete ControlTower IAM policies
            logger.info(f"\tDeleting ControlTower IAM policies")
            delete_ct_iam_policies(aws_session)

            ###### Delete ControlTower S3 buckets
            logger.info(f"\tDeleting ControlTower S3 buckets")
            delete_ct_buckets(aws_session, f"{account_id}-{region}")

            ###### Delete ControlTower Log Groups
            logger.info(f"\tDeleting ControlTower Log Groups")
            delete_ct_log_groups(aws_session)

            ###### Delete ControlTower Events rules
            logger.info(f"\tDeleting ControlTower Events rules")
            delete_ct_event_rules(aws_session)

        ###### Disable ControlTower Service Principal in AWS Organizations
        logger.info(f"Disabling ControlTower Service Principal in AWS Organizations")
        disable_ct_principal(aws_sessions[(root_account, region)])
    

    ############################################################################
    #                                   THE END
    ############################################################################
    logger.info(f"\nAWS Control Tower Clean-Up Ended")


if __name__ == '__main__':
    main()
