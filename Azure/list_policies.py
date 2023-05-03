from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import PolicyClient

# Acquire a credential object using CLI-based authentication.
credential = DefaultAzureCredential()

policy_client = PolicyClient(
        credential = credential,
        subscription_id = '1111111111111111111111'
    )

print('=========== Policy Definitions =============')
mg_policy_definitions = policy_client.policy_definitions.list_by_management_group(
    '1111111111111111111111',
    "policyType eq 'Custom'"
    )
for policy_def in mg_policy_definitions:
    print(f"Definition Name: {policy_def.name}\tDisplay Name: {policy_def.display_name}")
    
print('=========== Policy Assignments =============')
mg_policy_assignments = policy_client.policy_assignments.list_for_management_group(
    '1111111111111111111111', 
    "atScope()"
    )
for policy_assignment in mg_policy_assignments:
    print(f"Assignment Name: {policy_assignment.name}\tDisplay Name: {policy_assignment.display_name}")
    
