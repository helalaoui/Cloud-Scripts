############################################################################
#          Wipe-Out Script of the AWS Landing Zone Accelerator (LZA)
#
#    ******************   USE AT YOUR OWN RISK !!! *****************
#
# Script in steps:
#        1: Delete the LZA SCPs
#        2: Clean the 'Network' Account
#        3: Clean the 'Security' Account
#        4: Clean the 'Operations' Account
#        5: For each account:
#           5a: Delete the 'AWSAccelerator-SessionManagerEC2Role' IAM role
#           5b: Delete the AWSAccelerator-xxxxx Stacks
#           5c: Delete the LZA S3 Buckets
#           5d: Delete the LZA KMS keys
#           5e: Delete the LZA Log Groups
#           5f: Delete the IAM Policy 'AWSAccelerator-Default-Boundary-Policy'
#        6: Disable Security services
#        7: Delete Service Linked Roles
#        8: Delete the Root Account-specific stacks
#        9: Delete the Root-specific LZA S3 Buckets
#       10: Delete the Cost and Usage Report Definition
#       11: Delete the IAM Policy 'Default-Boundary-Policy'
#       12: Rename the CodeCommit Repo
#       13: Remove service delegations
#
#  Please fill-in the Parameters section before running this script.
#
#  The context for execution of this script should already have a valid
#    AWS authentication context: .aws/credentials and .aws/config
#
#  Version 2.4 - 2023-10-12
#  Author: Hicham El Alaoui - alaoui@it-pro.com
#
############################################################################

from datetime import datetime
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

# The network account that needs to be cleaned in Step 2:
lza_network_account_id = "22222222222"

# The security account that needs to be cleaned in Step 3:
lza_security_account_id = "33333333333"

# The operations account that needs to be cleaned in Step 4:
lza_operations_account_id = "44444444444"

# Logging level: choose either logging.INFO (recommended) or logging.DEBUG:
requested_verbose_level = logging.INFO

############################################################################
#                            LZA Internal Parameters
############################################################################

lza_core_stacks = [
    "AWSAccelerator-CustomizationsStack",
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
    "AWSAccelerator-NetworkAssociationsStack",
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

############################################################################
#                     Define Some Useful Functions
############################################################################
logger = logging.getLogger(__name__)


def delete_lza_scps():
    organizations = boto3.client('organizations')
    response = organizations.list_policies(Filter='SERVICE_CONTROL_POLICY')

    lza_scp_found = False
    for policy in response['Policies']:
        # Delete all policies whose name starts with the LZA prefix:
        if policy['Name'].startswith(lza_scp_name_prefix):
            removeAWSresources.detach_and_delete_scp(
                organizations_client = organizations, 
                policy_id = policy['Id'], 
                policy_name = policy['Name']
            )
            lza_scp_found = True

    if not lza_scp_found:
        logger.info("There are no LZA SCPs to delete!")


def clean_lza_network_account(aws_session):
    ec2 = aws_session.client('ec2')
    
    ##########################
    # Delete IPAMs
    logger.info(f"Deleting IPAMs")
    response = ec2.describe_ipams(
        Filters = [
            {
                'Name': "tag:Name",
                'Values': [lza_ipam_tag_name]
            }
        ]
    )
    for ipam in response['Ipams']:
        logger.info(f"\tDeleting IPAM {ipam['IpamId']} ...")
        delete_status = ec2.delete_ipam(
            DryRun = False,
            IpamId = ipam['IpamId'],
            Cascade = True
        )
    
    ##########################
    # Delete Transit Gateways
    logger.info(f"Deleting Transit Gateways")
    response = ec2.describe_transit_gateways()
    for transit_gateway in response['TransitGateways']:
        logger.info(f"\tDeleting Transit Gateway {transit_gateway['TransitGatewayId']} ...")
        
        # First delete all its VPC attachments:
        tg_response = ec2.describe_transit_gateway_vpc_attachments(
            Filters=[
                {
                    'Name': 'state',
                    'Values': [
                        'available',
                    ]
                },
            ],
        )
        for tg_vpc_attachment in tg_response['TransitGatewayVpcAttachments']:
            logger.info(f"\t\tDeleting Transit Gateway VPC attachment {tg_vpc_attachment['TransitGatewayAttachmentId']} ...")
            ec2.delete_transit_gateway_vpc_attachment(
                TransitGatewayAttachmentId=tg_vpc_attachment['TransitGatewayAttachmentId'],
                DryRun=False
            )
        
        if tg_response['TransitGatewayVpcAttachments']:
            logger.info(f"\t\tWaiting 10 seconds for the VPC attachments to finish deleting ...")
            sleep(10)
        
        ec2.delete_transit_gateway(
            TransitGatewayId=transit_gateway['TransitGatewayId'],
            DryRun=False
        )

    ##########################
    # Delete Resolver Rule Groups
    logger.info(f"Deleting Resolver Rule Groups")
    resolver = aws_session.client('route53resolver')
    response = resolver.list_firewall_rule_groups()
    for rule_group in response['FirewallRuleGroups']:
        logger.info(f"\tDeleting Resolver Rule Groups {rule_group['Name']} ...")
        resolver.delete_firewall_rule_group(
            FirewallRuleGroupId=rule_group['Id']
        )
    
    ##########################
    # Delete Firewall Policies
    logger.info(f"Deleting Network Firewall Policies")
    firewall = aws_session.client('network-firewall')
    response = firewall.list_firewall_policies()
    for firewall_policy in response['FirewallPolicies']:
        logger.info(f"\tDeleting Network Firewall Policy {firewall_policy['Name']} ...")
        firewall.delete_firewall_policy(
            FirewallPolicyName=firewall_policy['Name'],
            FirewallPolicyArn=firewall_policy['Arn']
        )
    


def clean_lza_security_account(aws_session):
    #########################################
    # Detele SSM parameters
    ssm = aws_session.client('ssm')
    
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
            logger.info(f"Deleting parameter '{parameter['Name']}'")
            ssm.delete_parameter(Name = parameter['Name'])
    else:
        logger.info(f"There are no SSM parameters to delete!")

    #########################################
    # Delete GuardDuty Detecors
    # guardduty = aws_session.client('guardduty')
    # response = guardduty.list_detectors()
    # for detector_id in response['DetectorIds']:
    #     logger.info(f"Deleting GuardDuty Detector ID '{detector_id}'")
    #     guardduty.delete_detector(
    #         DetectorId=detector_id
    #     )

def clean_lza_operations_account(aws_session):
    #########################################
    # Terminate the AwsAcceleratorManagedActiveDirectoryConfiguringInstance EC2 instance
    logger.info("Terminating the 'AwsAcceleratorManagedActiveDirectoryConfiguringInstance' instance")
    ec2 = aws_session.client('ec2')
    
    response = ec2.describe_instances(
        Filters=[
            {
                'Name': 'tag:Name',
                'Values': [
                    'AwsAcceleratorManagedActiveDirectoryConfiguringInstance',
                ]
            },
        ],
    )
    
    if response['Reservations']:
        instance_ids = [instance['InstanceId'] for instance in response['Reservations'][0]['Instances']]
        logger.info("\tTerminating instance IDs: " + str(instance_ids))
        ec2.terminate_instances(
            InstanceIds=instance_ids
        )
    else:
        logger.info("\tThere are no instance IDs to terminate.")
        
    #########################################
    # Unshare and Delete the Directories
    logger.info("Unshare and Delete the Directories")
    directory_service = aws_session.client('ds')
    
    response = directory_service.describe_directories()

    for directory in response['DirectoryDescriptions']:
        logger.debug('-' * 40 + 'Directory:')
        logger.debug(directory)
        if directory['Name'] == lza_directory_name:
            logger.debug(f"------- {directory['DirectoryId']}")
            sharing_response = directory_service.describe_shared_directories(OwnerDirectoryId = directory['DirectoryId'])
            
            nb_shared_directories = len(sharing_response['SharedDirectories'])
            for shared_directory in sharing_response['SharedDirectories']:
                logger.info(f"\t\tUnsharing shared directory: {shared_directory['SharedDirectoryId']}")
                logger.debug(shared_directory)
                
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
                logger.info(f"... Waiting {timer} seconds for the unshare operations to complete ({WAIT_SECONDS} seconds per shared directory, {nb_shared_directories} shared directories) ...")
                sleep(timer)

            logger.info(f"\tDeleting Directory {directory['DirectoryId']} ...")
            status = directory_service.delete_directory(DirectoryId = directory['DirectoryId'])


    ##########################################
    # Delete the LZA Managed Active Directory secrets
    logger.info(f"Deleting LZA Managed Active Directory secrets in the Operations Account")
    secrets_manager = aws_session.client('secretsmanager')
    response = secrets_manager.list_secrets(
        Filters=[
            {
                'Key': 'name',
                'Values': ['/accelerator']
            },
        ],
    )

    if response['SecretList']:
        for secret in response['SecretList']:
            logger.info(f"\tDeleting secret '{secret['ARN']}' in the Operations Account")
            secrets_manager.delete_secret(
                SecretId = secret['ARN'],
                ForceDeleteWithoutRecovery = True
            )
    else:
        logger.info("\tNo secrets to delete for the LZA Managed Active Directory!")


def delete_session_manager_role(aws_session, role_name):
    iam = aws_session.client('iam')
    
    role_deleted = removeAWSresources.delete_iam_role(
        iam_client = iam,
        role_name = role_name
    )

    if role_deleted:
        logger.info(f"IAM Role {role_name} deleted.")
    else:
        logger.info(f"There is no IAM Role {role_name} to delete!")


def delete_lza_account_stacks(aws_session, account_id, region):
    cloudformation = aws_session.client('cloudformation')
    delete_waiter = cloudformation.get_waiter('stack_delete_complete')
    
    stacks_to_delete = []
    stacks_deleted = False
    this_stack_deleted = False
    stack_to_wait = None
    for stack in lza_core_stacks:
        stack_name = f"{stack}-{account_id}-{region}"
        stacks_to_delete.append(stack_name)

        logger.info(f"\tDeleting stack {stack_name} ...")
        this_stack_deleted = removeAWSresources.delete_stack(
            cloudformation_client = cloudformation,
            stack_name = stack_name,
            wait_till_deleted = True,
            waiter = delete_waiter
        )
        stacks_deleted = stacks_deleted or this_stack_deleted
        stack_to_wait = stack_name
    
    # In case of: wait_till_deleted = False
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
        
        logger.info(f">>> All LZA core stacks were deleted ...")

    else:
        logger.info(f"There are no LZA core stacks to delete in this account!")


def delete_lza_account_buckets(aws_session, buckets_to_delete):
    s3_resource = aws_session.resource('s3')

    buckets_deleted = False
    for bucket_name in buckets_to_delete:
        delete_status = removeAWSresources.delete_bucket(s3_resource = s3_resource, bucket_name = bucket_name)
        buckets_deleted = buckets_deleted or delete_status
    
    if not buckets_deleted:
        logger.info("No buckets deleted!")

def delete_lza_iam_boundary_policy(aws_session, policy_arn):
    iam = aws_session.client('iam')

    policy_deleted = removeAWSresources.delete_iam_policy(
        iam_client = iam,
        policy_arn = policy_arn
    )

    if policy_deleted:
        logger.info(f"IAM Policy {policy_arn} deleted.")
    else:
        logger.info(f"There is no IAM Policy {policy_arn} to delete!")

def delete_lza_security_groups(aws_session):
    ec2 = aws_session.client('ec2')

    response = ec2.describe_security_groups(
        # GroupNames=[
        #     'Management',
        #     'AWSAcceleratorManagedActiveDirectory_mad_instance_sg',
        # ],
        Filters=[
            {
                "Name":"group-name",
                "Values": [
                    'Management',
                    'AWSAcceleratorManagedActiveDirectory_mad_instance_sg',
                ]
            }
        ]
    )

    if response['SecurityGroups']:
        for security_group in response['SecurityGroups']:
            logger.info(f"Deleting security group '{security_group['GroupName']}' (ID: {security_group['GroupId']}")
            ec2.delete_security_group(
                GroupId=security_group['GroupId'],
            )
    else:
        logger.info("There are no security groups to delete.")


def delete_lza_network_firewalls(aws_session):
    firewall_client = aws_session.client('network-firewall')
    response = firewall_client.list_firewalls()
    for firewall in response['Firewalls']:
        logger.info(f"Deleting Logging Configurations for Firewall '{firewall['FirewallName']}' ...")
        logging_configs = firewall_client.describe_logging_configuration(
            FirewallName=firewall['FirewallName'],
            FirewallArn=firewall['FirewallArn']
        )
        
        log_destination_list = logging_configs['LoggingConfiguration']['LogDestinationConfigs']
        # You can remove Logging Destination only one at a time:
        while log_destination_list:
            log_destination_list.pop()
            firewall_client.update_logging_configuration(
                FirewallName=firewall['FirewallName'],
                FirewallArn=firewall['FirewallArn'],
                LoggingConfiguration={
                    'LogDestinationConfigs': log_destination_list
                }
            )
        
        logger.info(f"Deleting Network Firewall '{firewall['FirewallName']}' ...")
        firewall_client.delete_firewall(
            FirewallName=firewall['FirewallName'],
            FirewallArn=firewall['FirewallArn']
        )
        
    return len(response['Firewalls'])


def delete_lza_endpoints(aws_session):
    ec2 = aws_session.client('ec2')
    response = ec2.describe_vpc_endpoints(
        Filters=[
            {
                'Name': 'vpc-endpoint-state',
                'Values': [
                    'available',
                ]
            },
        ]
    )
    vpce_list = [vpce['VpcEndpointId'] for vpce in response['VpcEndpoints']]
    if vpce_list:
        logger.info(f"Deleting VPC Endpoints " + str(vpce_list))
        ec2.delete_vpc_endpoints(
            DryRun=False,
            VpcEndpointIds=vpce_list
        )
    else:
        logger.info(f"There are no VPC Endpoints to delete!")

def delete_lza_route_tables(aws_session):
    ec2 = aws_session.client('ec2')
    response = ec2.describe_route_tables(
    )
    if response['RouteTables']:
        for route_table in response['RouteTables']:
            # print(route_table['Associations'])
            is_main_route_table = False
            for association in route_table['Associations']:
                if association['Main']:
                    is_main_route_table = True
                    logger.info(f"Main Route Table is {route_table['RouteTableId']}")
                elif association['AssociationState']['State'] == 'associated':
                    logger.info(f"Disassociating Route Table {route_table['RouteTableId']} from Subnet {association['SubnetId']}")
                    ec2.disassociate_route_table(
                        AssociationId=association['RouteTableAssociationId']
                    )
            
            if not is_main_route_table:
                logger.info(f"Deleting Route Table {route_table['RouteTableId']}")
                ec2.delete_route_table(
                    DryRun=False,
                    RouteTableId=route_table['RouteTableId']
                )
    else:
        logger.info(f"There are no Route Tables to Delete!")


def delete_lza_subnets(aws_session):
    ec2 = aws_session.client('ec2')
    response = ec2.describe_subnets(
        Filters=[
            {
                'Name': 'state',
                'Values': [
                    'available',
                ]
            },
        ],
    )
    if response['Subnets']:
        for subnet in response['Subnets']:
            logger.info(f"Deleting subnet {subnet['SubnetId']}")
            ec2.delete_subnet(
                DryRun=False,
                SubnetId=subnet['SubnetId']
            )
    else:
        logger.info(f"There are no Subnets to Delete!")
    


def delete_lza_service_linked_roles(aws_session):
    iam = aws_session.client('iam')

    for role in lza_service_linked_roles:
        logger.debug(f"\t----- Deleting service-linked role '{role}'")
        
        try:    
            response = iam.delete_service_linked_role(RoleName=role)
        except ClientError as err:
            logger.debug('*'*20 + f" IAM service-linked Role {role} Not Found! Error message:")
            logger.debug("*"*10 + str(err))
        else:
            logger.info(f"\t\tIAM service-linked role {role} deleted.")
            logger.debug(response)






############################################################################
#                         Start of the Script
############################################################################


def main():
    logging.basicConfig(format='%(message)s')
    logger.setLevel(requested_verbose_level)

    #########################################
    # Basic Checks:
    if lza_network_account_id not in lza_non_root_accounts:
        logger.info(f"Network account ID '{lza_network_account_id}' not found in the provided list of accounts!\nPlease check the value of the lza_network_account_id parameter in the parameters section of this script.\nAborting.")
        exit(1)

    if lza_security_account_id not in lza_non_root_accounts:
        logger.info(f"Security account ID '{lza_security_account_id}' not found in the provided list of accounts!\nPlease check the value of the lza_security_account_id parameter in the parameters section of this script.\nAborting.")
        exit(1)

    if lza_operations_account_id not in lza_non_root_accounts:
        logger.info(f"Operations account ID '{lza_operations_account_id}' not found in the provided list of accounts!\nPlease check the value of the lza_operations_account_id parameter in the parameters section of this script.\nAborting.")
        exit(1)

    #########################################
    # Build the list of all accounts:
    all_lza_accounts = [(account_id, account_name) for account_id, account_name in lza_non_root_accounts.items()]
    all_lza_accounts.append((root_account, root_profile))
    logger.debug("All LZA Accounts:")
    logger.debug(all_lza_accounts)

    #########################################
    # Extended regions = regions + 'us-east-1'
    extended_regions = regions
    if 'us-east-1' not in regions: extended_regions = regions + ['us-east-1']


    #########################################
    # Build the list of connections to all accounts in all regions:
    aws_sessions = {}

    for region in extended_regions:    
        for account_id, account_name in all_lza_accounts:
            aws_sessions[(account_id, region)] = boto3.session.Session(profile_name=account_name, region_name=region)


    ############################################################################
    #                Step 6: Disable Security services
    ############################################################################
    logger.info('\n' + '>'*10 + f" Step 6: Disable Security services")

    for region in regions:
        print('-'*10 + f"Region '{region}'")
        # Disable GuardDuty in the Security account:
        aws_session = aws_sessions[(root_account, region)]
        removeAWSresources.disable_guardduty(aws_session)

        # Disable Macie and SecurityHub in all other accounts:
        for account_id, account_name in all_lza_accounts:
            print('-'*30 + f"Account '{account_name}' ({account_id})")
            aws_session = aws_sessions[(account_id, region)]
            removeAWSresources.disable_macie(aws_session)
            removeAWSresources.disable_security_hub(aws_session)

    logger.info(f"\nWaiting 30 seconds for the services to finish disabling ...\n")
    sleep(30)


    ############################################################################
    #                 Delete the LZA SCPs
    ############################################################################
    logger.info('\n' + '>'*10 + " Step 1: Delete the LZA SCPs ")
    delete_lza_scps()

    ############################################################################
    #          Step 2: Clean the 'Network' Account
    ############################################################################
    for region in regions:
        logger.info('\n' + '>'*10 + " Step 2: Clean the 'Network' Account ({lza_network_account_id}) in region '{region}'")

        # To be able to delete the security groups in the 'Network' account, we need first
        # to delete all security groups, network firewalls and VPC-Endpoints in all other accounts
        nb_firewalls_deleted = 0
        for account_id, account_name in all_lza_accounts:
            if account_id == lza_network_account_id: continue
            
            aws_session = aws_sessions[(account_id, region)]

            logger.info('\n' + '='*80 + '\n' + ' '*5 + f"Deleting Security Groups, Route Tables, VPC-Endpoints and Network Firewalls in Account {account_name} ({account_id}) in region {region}\n" + '='*80)
            delete_lza_security_groups(aws_session)
            # delete_lza_subnets(aws_session)
            delete_lza_route_tables(aws_session)
            delete_lza_endpoints(aws_session)
            nb_firewalls_deleted += delete_lza_network_firewalls(aws_session)

        if nb_firewalls_deleted:
            wait_minutes = 15
            logger.info(f"Waiting {wait_minutes} minutes for the Network Firewalls to finsh deleting ...")
            sleep(60 * wait_minutes)
            
        # Now we can delete the Security Groups in the 'Network' account
        account_id = lza_network_account_id
        account_name = lza_non_root_accounts[lza_network_account_id]
        logger.info('\n' + '='*80 + '\n' + ' '*5 + f"Deleting Security Groups in Account {account_name} ({account_id}) in region {region}\n" + '='*80)
        aws_session = aws_sessions[(account_id, region)]
        delete_lza_security_groups(aws_session)
        clean_lza_network_account(aws_session)
        
    ############################################################################
    #           Step 3: Clean the 'Security' Account
    ############################################################################
    for region in regions:
        logger.info('\n' + '>'*10 + f" Step 3: Clean the 'Security' Account ({lza_security_account_id}) in region '{region}'")
        aws_session = aws_sessions[ (lza_security_account_id, region) ]
        clean_lza_security_account(aws_session)

    ############################################################################
    #                 Step 4: Clean the 'Operations' Account
    # - Terminate the AwsAcceleratorManagedActiveDirectoryConfiguringInstance EC2 instance
    # - Unshare and Delete the Directories
    # - Delete the LZA Managed Active Directory secrets
    ############################################################################
    account_name = lza_non_root_accounts[lza_operations_account_id]

    for region in regions:
        logger.info('\n' + '>'*10 + " Step 4: Clean the 'Operations' Account ({lza_operations_account_id}) in region '{region}'")
        aws_session = aws_sessions[(lza_operations_account_id, region)]
        clean_lza_operations_account(aws_session)

    ############################################################################
    #                        Step 5 (for each account):
    ############################################################################

    for region in regions:
        for account_id, account_name in all_lza_accounts:
            logger.info('\n' + '='*80 + '\n' + ' '*5 + f"Cleaning Account {account_name} ({account_id}) in region {region}\n" + '='*80)
            aws_session = aws_sessions[(account_id, region)]

            ############################################################################
            #               Step 5a: Delete security groups
            ############################################################################
#             logger.info('\n' + '>'*10 + f" Step 5a: Delete security groups in account {account_name} ")
#             delete_lza_security_groups(aws_session)

            ############################################################################
            #    Step 5a: Delete the 'AWSAccelerator-SessionManagerEC2Role' IAM role
            ############################################################################
            logger.info('\n' + '>'*10 + " Step 5a: Delete the 'AWSAccelerator-SessionManagerEC2Role' IAM role ")
            role_name = f"{lza_session_manager_ec2_role}-{region}"
            delete_session_manager_role(aws_session, role_name)
            
            ############################################################################
            #              Step 5b: Delete the AWSAccelerator-xxxxx Stacks
            ############################################################################
            logger.info('\n' + '>'*10 + " Step 5b: Delete the LZA core stacks (AWSAccelerator-xxxxx)")
            delete_lza_account_stacks(aws_session, account_id, region)

            ############################################################################
            #           Step 5d: Delete the LZA S3 Buckets
            ############################################################################
            logger.info('\n' + '>'*10 + f" Step 5d: Delete the LZA S3 Buckets in account '{account_name}'")
            buckets_to_delete = [f"{bucket}-{account_id}-{region}" for bucket in lza_buckets]
            delete_lza_account_buckets(aws_session, buckets_to_delete)

            ############################################################################
            #           Step 5e: Delete the LZA KMS keys
            ############################################################################
            logger.info('\n' + '>'*10 + f" Step 5e: Delete the LZA KMS keys in account '{account_name}'")
            kms = aws_sessions[(account_id, region)].client('kms')
            removeAWSresources.delete_keys_by_tag(kms_client = kms, target_tag_name = lza_tag_name, target_tag_value = lza_tag_value)

            ############################################################################
            #                Step 5f: Delete Log Groups
            ############################################################################
            logger.info('\n' + '>'*10 + f" Step 5f: Delete Log Groups in account {account_name} in region '{region}' ")
            cloudwatch_client = aws_sessions[(account_id, region)].client('logs')
            for prefix in lza_log_groups_prefixes:
                removeAWSresources.delete_log_groups_with_prefix(cloudwatch_client, prefix)

            ############################################################################
            #    Step 5g: Delete the IAM Policy 'AWSAccelerator-Default-Boundary-Policy'
            ############################################################################
            logger.info('\n' + '>'*10 + f" Step 5g: Delete the IAM Policy 'AWSAccelerator-Default-Boundary-Policy' in account {account_name} ")
            policy_arn = f"arn:aws:iam::{account_id}:policy/AWSAccelerator-Default-Boundary-Policy"
            delete_lza_iam_boundary_policy(aws_sessions[(account_id, 'us-east-1')], policy_arn)

            
    # Separator (End of core accounts cleaning)
    logger.info('\n' + '='*80)

    ############################################################################
    #                Step 7: Delete Service Linked Roles
    ############################################################################
    logger.info('\n' + '>'*10 + f" Step 7: Delete Service Linked Roles")

    for region in regions:
        for account_id, account_name in all_lza_accounts:
            logger.info(f"\tDeleting service-linked roles in account {account_name} in region '{region}' ")
            aws_session = aws_sessions[(account_id, region)]
            delete_lza_service_linked_roles(aws_session)


    ############################################################################
    #           Step 8: Delete the Root Account-specific stacks
    ############################################################################
    logger.info('\n' + '>'*10 + f" Step 8: Delete the Root Account-specific stacks ")

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

            this_stack_deleted = removeAWSresources.delete_stack(
                cloudformation_client = cloudformation,
                stack_name = stack_name,
                wait_till_deleted = True,
                waiter = delete_waiter
            )
            stacks_deleted = stacks_deleted or this_stack_deleted

        # Delete the LZA Installer Stack
        stack_name = lza_installer_stack

        this_stack_deleted = removeAWSresources.delete_stack(
            cloudformation_client = cloudformation,
            stack_name = stack_name,
            wait_till_deleted = True,
            waiter = delete_waiter
        )
        stacks_deleted = stacks_deleted or this_stack_deleted

        if not stacks_deleted:
            logger.info(f"There are no root account-specific stacks to delete in region {region}")

    ###########################################
    #  Delete the root account stacks specific to 'us-east-1'
    region = 'us-east-1'
    cloudformation = aws_sessions[(account_id, region)].client('cloudformation')
    delete_waiter = cloudformation.get_waiter('stack_delete_complete')
    stacks_deleted = False
    this_stack_deleted = False

    for stack in lza_root_stacks_in_us_east_1:
        stack_name = f"{stack}-{account_id}-{region}"

        this_stack_deleted = removeAWSresources.delete_stack(
            cloudformation_client = cloudformation,
            stack_name = stack_name,
            wait_till_deleted = True,
            waiter = delete_waiter
        )
        stacks_deleted = stacks_deleted or this_stack_deleted
        stack_to_wait = stack_name

    if not stacks_deleted:
        logger.info(f"There are no root account-specific stacks to delete in region {region}")

    ############################################################################
    #           Step 9: Delete the Root-specific LZA S3 Buckets
    ############################################################################
    logger.info('\n' + '>'*10 + f" Step 9: Delete the Root-specific LZA S3 Buckets ")

    buckets_to_delete = []
        
    for region in extended_regions:
        buckets_to_delete += [f"aws-accelerator-{bucket}-{account_id}-{region}" for bucket in lza_root_buckets]
        # buckets_to_delete += [f"cdk-accel-assets-{account_id}-{region}"]

    buckets_deleted = False

    s3_resource = aws_sessions[(root_account, 'us-east-1')].resource('s3')
    for bucket_name in buckets_to_delete:
        delete_status = removeAWSresources.delete_bucket(s3_resource = s3_resource, bucket_name = bucket_name)
        buckets_deleted = buckets_deleted or delete_status

    if not buckets_deleted:
        logger.info("No buckets deleted!")

    ############################################################################
    #      Step 10: Delete the Cost and Usage Report Definition
    ############################################################################
    logger.info('\n' + '>'*10 + f" Step 10: Delete the Cost and Usage Report Definition")

    cost_usage = aws_sessions[(root_account, 'us-east-1')].client('cur')

    try:
        logger.debug(f"Deleting Cost and Usage Report {lza_cost_usage_report_name} ...")
        cost_usage.delete_report_definition(
            ReportName = lza_cost_usage_report_name
        )
    except ClientError as err:
        logger.debug(f"\tCost and Usage Report {lza_cost_usage_report_name} Not Found!")
        logger.debug('*'*20 + f"Error message:")
        logger.debug("*"*10 + str(err))


    ############################################################################
    # Step 11: Delete the IAM Policy 'Default-Boundary-Policy' of the Root account in us-east-1
    ############################################################################
    logger.info('\n' + '>'*10 + f" Step 11: Delete the IAM Policy 'Default-Boundary-Policy' of the Root account in us-east-1 ")

    region = 'us-east-1'
    iam = aws_sessions[(root_account, region)].client('iam')

    policy_arn = f"arn:aws:iam::{root_account}:policy/Default-Boundary-Policy"

    policy_deleted = removeAWSresources.delete_iam_policy(
        iam_client = iam,
        policy_arn = policy_arn
    )

    if policy_deleted:
        logger.info(f"IAM Policy {policy_arn} deleted.")
    else:
        logger.info(f"There is no IAM Policy {policy_arn} to delete!")

    ############################################################################
    #                Step 12: Rename the CodeCommit Repo
    ############################################################################
    for region in regions:
        logger.info('\n' + '>'*10 + f" Step 12: Rename the CodeCommit Repo in region '{region}' ")

        codecommit = aws_sessions[ (root_account, region) ].client('codecommit')
        
        try:
            response = codecommit.get_repository(repositoryName = lza_repository_name)
        except ClientError as err:
            logger.info(f"CodeCommit Repository {lza_repository_name} Not Found!")
            logger.debug("*"*10 + str(err))
        else:
            now = datetime.now()
            new_name = lza_repository_name + '_' + now.strftime("%Y-%m-%d_%Hh%Mm%Ss")
            logger.info(f"Renaming the '{lza_repository_name}' repository to '{new_name}'")
            codecommit.update_repository_name(oldName = lza_repository_name, newName = new_name)

    ############################################################################
    #                Step 13: Remove service delegations
    ############################################################################
    logger.info('\n' + '>'*10 + f" Step 13: Remove service delegations")
    delegations_found = False

    for region in regions:
        for account_id, account_name in all_lza_accounts:
            logger.debug(f"Remove service delegations in account {account_name} in region '{region}' ")

            organizations = aws_sessions[(root_account, region)].client('organizations')
            
            try:
                response = organizations.list_delegated_services_for_account(AccountId = account_id)
            except ClientError as err:
                logger.debug(f"\tNo delegated services in Account {account_name}")
            else:
                delegations_found = True
                for delegated_service in response['DelegatedServices']:
                    service = delegated_service['ServicePrincipal']
                    
                    logger.info(f"Removing service delegation for account {account_name} on service {service}")
                    organizations.deregister_delegated_administrator(
                        AccountId = account_id,
                        ServicePrincipal = service
                    )

    if not delegations_found:
        logger.info(f"No service delegations found!")




    ############################################################################
    #                                   THE END
    ############################################################################

    logger.info(f"\nAWS LZA Wipe-Out Ended")



if __name__ == '__main__':
    main()

