############################################################################
#                     Azure Landing Zone Wipe-Out Script
#
#    ******************   USE AT YOUR OWN RISK !!! *****************
#
# Script in 3 phases:
#   - Phase 1: Deletes Resource Groups whose name ends with a given suffix.
#   - Phase 1 Dry Run: Runs Phase 1 without actually deleting the resource groups.
#                      Prints the list of resource groups that would be deleted.
#   - Phase 2: Moves all subscriptions under The Root Management Group.
#   - Phase 3: Deletes All Management Groups of the target Environment.
#               This would also automatically delete the Policy/Initiative assignments
#               and definitions that are scoped to these management groups.
#
#  Built for the v2.2 Landing Zone deployment scripts.
#  The context for execution of this script should already have a valid
#    Azure authentication context (e.g. Azure CLI az login already done).
#
#  Version 1.6.2 - 2023-06-28
#  Author: Hicham El Alaoui - alaoui@it-pro.com
############################################################################

# Constants - Do not modify
VERBOSE_NONE   = 1
VERBOSE_LOW    = 2
VERBOSE_MEDIUM = 3
VERBOSE_HIGH   = 4

PHASE1_DESCRIPTION = "Delete Resource Groups that have the landing zone suffix"
PHASE2_DESCRIPTION = "Move all subscriptions to the Root management group"
PHASE3_DESCRIPTION = "Delete all Management Groups under the selected organization management group"

############################################################################
#                                 Parameters
############################################################################
# Please note that command line parameters take precedence over the following parameters.
# Please run this script with a -h argument for a help on the command line syntax.
#
target_tenant_id = ''
organization_top_mgmt_group_id = ''

# The name suffix used to identify the resource groups that need to be deleted:
resource_suffix = ''

# Option to check the value of a tag on the resources before they are deleted.
check_resource_tags_before_delete = True
organization_tag_name = 'NomDuSysteme'
organization_tag_value = ''

# Phases you want to run:
run_phase = {
    'Phase 1': True,
    'Phase 2': True,
    'Phase 3': True
}

# Message verbose level you want. Options: VERBOSE_NONE, VERBOSE_LOW, VERBOSE_MEDIUM,
#    or VERBOSE_HIGH. Recommended: VERBOSE_LOW.
requested_verbose_level = VERBOSE_LOW

############################################################################
#                             End of Parameters
############################################################################

from time import sleep
import sys
import argparse

from azure.identity import DefaultAzureCredential, AzureCliCredential
from azure.mgmt.resource import ResourceManagementClient, SubscriptionClient
from azure.mgmt.managementgroups import ManagementGroupsAPI
from azure.core.exceptions import ResourceNotFoundError


# Verbose Print
def vprint(message, message_verbose_level=VERBOSE_LOW):
    if message_verbose_level <= requested_verbose_level:
        print(message)
    return

############################################################################
#               Check if there are command line arguments
# If there are arguments, then they take precedence over the above parameters
# Please run this script with a -h for a help on the command line syntax.
############################################################################
dry_run_phase_1 = False
delete_confirmation = True
if len(sys.argv) > 1:
    parser = argparse.ArgumentParser(description="Parser for the wiper script", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--dry-run-phase-1", action="store_true", dest="dry_run_phase_1", help=f"Dry run Phase 1 to get the list of Resource Groups to be deleted.")
    parser.add_argument("--no-delete-confirmation", action="store_true", dest="no_delete_confirmation", help=f"Delete the Resource Groups without asking for confirmation.")
    parser.add_argument("--run-phase-1", action="store", dest="run_phase_1", choices=["True", "False"], default="False", help=f"Run Phase 1: {PHASE1_DESCRIPTION}.")
    parser.add_argument("--run-phase-2", action="store", dest="run_phase_2", choices=["True", "False"], default="False", help=f"Run Phase 2: {PHASE2_DESCRIPTION}.")
    parser.add_argument("--run-phase-3", action="store", dest="run_phase_3", choices=["True", "False"], default="False", help=f"Run Phase 3: {PHASE3_DESCRIPTION}.")
    parser.add_argument("--tenant-id", action="store", dest="tenant_id", required=True, help="ID of the target Azure tenant.")
    parser.add_argument("--org-top-mgmt-group-id", action="store", dest="org_id", required=True, help="ID of the target Azure tenant.")
    parser.add_argument("--check-org-tag", action="store", dest="check_tag", choices=["True", "False"], default="False", help=f"Check the resources '{organization_tag_name}' tag before deletion.")
    parser.add_argument("--org-tag", action="store", dest="org_tag", help=f"Value of the Azure Tag '{organization_tag_name}' that should be attached to the resources.")
    parser.add_argument("--rg-name-suffix", action="store", dest="rg_suffix", default='cac-001', help="Name suffix of the resource groups to delete.")

    args = parser.parse_args()

    if args.dry_run_phase_1:
        dry_run_phase_1 = True
        run_phase["Phase 1"] = True
        run_phase["Phase 2"] = False
        run_phase["Phase 3"] = False
        requested_verbose_level = VERBOSE_NONE # The script output in dry-run in only the list of resource groups and resources to be deleted.
    else:
        vprint("I have command line arguments:", VERBOSE_MEDIUM)
        vprint(f"sys.argv = {sys.argv}", VERBOSE_MEDIUM)
        vprint(f"argparse args = {vars(args)}", VERBOSE_MEDIUM)

        dry_run_phase_1 = False
        delete_confirmation = not args.no_delete_confirmation

        run_phase["Phase 1"] = eval(args.run_phase_1)
        run_phase["Phase 2"] = eval(args.run_phase_2)
        run_phase["Phase 3"] = eval(args.run_phase_3)

    target_tenant_id = args.tenant_id
    organization_top_mgmt_group_id = args.org_id
    organization_tag_value = args.org_tag
    check_resource_tags_before_delete = eval(args.check_tag)
    resource_suffix = args.rg_suffix
            
else:
    vprint("No commad line arguments ... Using embedded script parameters", VERBOSE_MEDIUM)

vprint("\n================ Starting Script with the following parameters:", VERBOSE_MEDIUM)
vprint(f"target_tenant_id = {target_tenant_id}", VERBOSE_MEDIUM)
vprint(f"organization_top_mgmt_group_id = {organization_top_mgmt_group_id}", VERBOSE_MEDIUM)
vprint(f"organization_tag_value = {organization_tag_value}", VERBOSE_MEDIUM)
vprint("run_phase:", VERBOSE_MEDIUM)
vprint(run_phase, VERBOSE_MEDIUM)
vprint(f"resource_suffix = {resource_suffix}", VERBOSE_MEDIUM)
vprint(f"check_resource_tags_before_delete = {check_resource_tags_before_delete}", VERBOSE_MEDIUM)
vprint("\n=======================================================\n")

############################################################################
#                  Connect to Azure and Run Basic Checks
############################################################################
# Check the resource_suffix length:
if len(resource_suffix) < 6:
    vprint("The provided suffix for the resource names (resource_suffix) is too short!")
    exit(1)
    
# Acquire a credential object. If Run from an Azure CLI context (after "az login"), will take the credentials of Azure CLI.
credential = DefaultAzureCredential(exclude_shared_token_cache_credential=True)

# List subscriptions.
# Needed also to check the current tenant_id.
sub_client = SubscriptionClient(credential)
vprint("Gathering the list of subscriptions and their resource groups ...\n")
all_subscriptions = [item for item in sub_client.subscriptions.list()]

if not all_subscriptions:
    vprint("There are no subscriptions in your active tenant.")
    credential.close()
    exit(1)

current_tenant_id = all_subscriptions[0].tenant_id

# Check if we are on the right tenant:
if current_tenant_id != target_tenant_id:
    vprint("You are running this script from a tenant that is different from the specified tenant.")
    vprint("Execution (runtime) tenant ID:    " + current_tenant_id)
    vprint("Tenant ID parameter you provided: " + target_tenant_id)
    vprint("Exiting ...")
    credential.close()
    exit(1)    

############################################################################
#                  Collect the List of Target Subscriptions 
############################################################################
root_mgmt_group = None
mg_client = ManagementGroupsAPI(credential)
all_mgmt_groups = [group for group in mg_client.entities.list()]

# Scroll all mgmt groups in order to identify:
#   - the list of subscriptions which are under the organization's top management group
#   - the root mgmt group
wipe_out_scope = organization_top_mgmt_group_id

subscriptions_in_scope = []
vprint(f"Scrolling all mgmt groups to identify the root mgmt group and the subscription that are in the scope ...", VERBOSE_MEDIUM)
for group in all_mgmt_groups:
    vprint(f"Group: {group.name}\t{group.type}", VERBOSE_MEDIUM)
    vprint(group, VERBOSE_HIGH)
    # In the list here you have the entire hierarchical tree, including the subscriptions,
    if group.type == 'Microsoft.Management/managementGroups':

        # Identification of the Root Mgmt Group:
        if not group.parent_name_chain and group.display_name == 'Tenant Root Group':
            vprint(f"======Root Mgmt Group Identified: {group.name}", VERBOSE_MEDIUM)
            root_mgmt_group = group

    elif group.type == '/subscriptions' : # This is a subscription
        # Collect only the subscriptions which are under the organization top management group
        # For that purpose we need to check the whole parent chain
        for parent in group.parent_name_chain:
            if parent == wipe_out_scope:
                subscriptions_in_scope.append(
                        {
                            'name': group.display_name,
                            'id': group.name,
                        }
                    )
                vprint(f"Adding Subscription: {group.display_name}", VERBOSE_MEDIUM)
                break

############################################################################
#                       Phase 1: Delete Resource Groups
############################################################################
vprint(f"\n============ Phase 1: {PHASE1_DESCRIPTION}\n")
if run_phase['Phase 1']:

    ### Gathering the list of subscriptions that have groups that need to be deleted
    subscriptions_to_wipe = []
    rg_delete_count = 0

    for sub in all_subscriptions: 
        # We need to loop on all_subscriptions because the subscriptions might have been moved manually out of the organization mgmt group. 
        vprint(f"Subscription: {sub.display_name}:")
        vprint(sub, VERBOSE_HIGH)
        
        # Retrieve the list of resource groups of this subscription
        resource_client = ResourceManagementClient(credential, sub.subscription_id)

        # Filter resource groups that have the right suffix. If one found, this makes 
        # the current subscription a target subscription
        target_groups = []
        network_watcher_rg_candidate = None

        resource_groups = [group for group in resource_client.resource_groups.list()]

        for group in resource_groups:
            vprint(group, VERBOSE_HIGH)
            if group.name.endswith(resource_suffix):
                if dry_run_phase_1:
                    vprint(group.name, VERBOSE_NONE)
                else:
                    vprint(f"\t{group.name}", VERBOSE_LOW)
                
                # For added security, check if all the resources of this resource group have the right tag 
                for resource in resource_client.resources.list_by_resource_group(group.name):
                    if dry_run_phase_1:
                        vprint(f"\t{resource.name}", VERBOSE_NONE)
                    else:
                        vprint(f"\t\t{resource.name}", VERBOSE_LOW)

                    if check_resource_tags_before_delete:
                        if resource.tags:
                            # If there are tags, then there should be one named {organization_tag_name}, otherwise 
                            # this means this resource was not created by the LandingZone script.
                            resource_org_tag_found = False
                            resource_org_tag = ''
                            for tag_name, tag_value in resource.tags.items():
                                if tag_name == organization_tag_name:
                                    resource_org_tag_found = True
                                    resource_org_tag = tag_value
                                vprint(f"\t\t\t{tag_name:<40}\t{tag_value}", VERBOSE_MEDIUM)
                            if not resource_org_tag_found:
                                vprint(f"\nThe resource {resource.name} has tags but none of them is named '{organization_tag_name}'. This resource might have been created manually. Aborting ...")
                                credential.close()
                                exit(1)
                            if resource_org_tag != organization_tag_value:
                                vprint(f"\nThe resource {resource.name} has a wrong value for tag '{organization_tag_name}'. Value found = {resource_org_tag}. Value expected = {organization_tag_value}. Please check the parameters of this script. Aborting ...")
                                credential.close()
                                exit(1)
                        else:
                            vprint(f"==== No tags on {resource.name}", VERBOSE_MEDIUM)
                            
                target_groups.append(group)

            elif group.name == 'NetworkWatcherRG':
                network_watcher_rg_candidate = group
            
        if not target_groups:
            vprint(f"... No target resource groups in Subscription {sub.display_name}. Skipping ...")
            continue
        
        # Else, (if there are target resource groups in this subscription) then this is a subscription to wipe

        # Since this is a target subscription, add the NetworkWatcherRG resource group (if any) to the target group list
        if network_watcher_rg_candidate:
            target_groups.append(network_watcher_rg_candidate)
            vprint(f"\t\t{network_watcher_rg_candidate.name} in {network_watcher_rg_candidate.location}")
        
        # Build the list of target subscriptions and their target groups
        subscriptions_to_wipe.append(
                {
                    'name': sub.display_name,
                    'id': sub.subscription_id,
                    'resource_groups': target_groups,
                    'resource_client': resource_client
                }
            )
        rg_delete_count += len(target_groups)


    ### Delete the target list of resource groups (unless this is a dry-run phase)
    if dry_run_phase_1:
        vprint("\nThis is a dry-run of phase 1. No resource groups will be deleted.", VERBOSE_MEDIUM)
    else:
        if rg_delete_count:
            if delete_confirmation:
                user_input = input(f"\nAre you sure you want to delete permanently ALL the above {rg_delete_count} resource groups and all resources included in those groups ? (Yes/No): ").lower()
            else:
                user_input = 'yes'

            if user_input == 'yes':
                for sub in subscriptions_to_wipe:
                    vprint("Subscription: " + sub['name'], VERBOSE_LOW)
                    vprint(sub, VERBOSE_HIGH)
                    
                    # Delete resource groups
                    for group in sub['resource_groups']:
                        vprint(f"\tStarting Deletion of resource group {group.name}")
                        vprint(group, VERBOSE_HIGH)
                        sub['resource_client'].resource_groups.begin_delete(group.name)
            else:
                vprint("No confirmation for deletion. Skipping Phase 1!")
        else:
            vprint("\nThere are no resource groups to delete.")
    
else: # run_phase['Phase 1'] == False
    vprint("=> You chose to skip Phase 1. Skipping ...")

############################################################################
#       Phase 2: Move all subscriptions under The Root Management Group
############################################################################
vprint(f"\n============ Phase 2: {PHASE2_DESCRIPTION}\n")

if run_phase['Phase 2']:
    # Move the target subscriptions under the root management group:
    if subscriptions_in_scope:
        for sub in subscriptions_in_scope:
            vprint(f"Moving Subscription '{sub['name']}' under root ...", VERBOSE_LOW)
            mg_client.management_group_subscriptions.create(root_mgmt_group.name, sub['id'])

        WAIT_SECONDS = 5
        # Wait WAIT_SECONDS seconds (for each move operation) until the move operations are completed
        timer = WAIT_SECONDS * len(subscriptions_in_scope)
        vprint(f"... Waiting {timer} seconds for the move operations to complete ...")
        sleep(timer)
    else:
        vprint(f"There are no subscriptions under the organization top management group {organization_top_mgmt_group_id}.")
else:
    vprint("=> You chose to skip Phase 2. Skipping ...")

############################################################################
#       Phase 3: Delete All Management Groups of the target Environment
############################################################################
vprint(f"\n============ Phase 3: {PHASE3_DESCRIPTION}\n")

if run_phase['Phase 3']:
    nb_flights = 10
else:
    nb_flights = 0
    vprint("=> You chose to skip Phase 3. Skipping ...")

# Management groups cannot be deleted if they have children
# Therefore we need to do many iterations and each time delete the bottom management groups (tree leafs)
for i in range(nb_flights):
    vprint(f"----- Flight {i+1}")
    # Scroll all mgmt groups in order to collect the list of mgmt groups which are under the organization's top management group
    mgmt_groups_to_delete = []
    if not mg_client:
        mg_client = ManagementGroupsAPI(credential)
    for group in mg_client.entities.list():
        # In the list of groups you have the entire hierarchical tree, including the subscriptions,
        # we can only delete mgmt groups that are at the lowest level (leaf)
        if group.type == 'Microsoft.Management/managementGroups' and group.number_of_descendants == 0:
            vprint(group, VERBOSE_HIGH)
            # Top level organization mgmt group:
            if group.name == organization_top_mgmt_group_id:
                mgmt_groups_to_delete.append(group)
                vprint(f"===== Delete candidate (leaf, Top organization group): {group.name}", VERBOSE_MEDIUM)
            else:
                # Check if the mgmt groups is under the organization top management group
                # For that purpose we need to check all the parent chain
                for parent in group.parent_name_chain:
                    if parent == organization_top_mgmt_group_id:
                        mgmt_groups_to_delete.append(group)
                        vprint(f"===== Delete candidate (leaf): {group.name}", VERBOSE_MEDIUM)
                        break

    if not mgmt_groups_to_delete:
        if i == 0:
            vprint(f"No management groups to delete. Please check if your organization top management group ID is {organization_top_mgmt_group_id}.")
        else:
            vprint("\nNo more management groups to delete.")
        break
    
    mg_delete_count = 0
    for group in mgmt_groups_to_delete:
        # In each iteration delete only the bottom management groups (tree leafs)
        vprint(f"Starting Deletion of Management Group {group.display_name}.")
        vprint(group, VERBOSE_HIGH)
        try:
            mg_client.management_groups.begin_delete(group.name)
        except ResourceNotFoundError as err:
            vprint(f"\tManagement Group {group.display_name} not found. Perhaps already deleted in the previous flight.")
        else:
            mg_delete_count += 1

    WAIT_SECONDS = 6
    # Wait WAIT_SECONDS seconds (for each delete operation) until the delete operations are completed
    timer = WAIT_SECONDS * mg_delete_count
    vprint(f"... Waiting {timer} seconds ({WAIT_SECONDS} seconds per management group) for the delete operations to complete ...")
    sleep(timer)
    
    # Continue to next flight

credential.close()
vprint("End of Script", VERBOSE_MEDIUM)
exit(0)
