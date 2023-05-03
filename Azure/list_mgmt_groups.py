from azure.identity import DefaultAzureCredential, AzureCliCredential
from azure.mgmt.resource import ResourceManagementClient, SubscriptionClient
from azure.mgmt.managementgroups import ManagementGroupsAPI
from azure.core.exceptions import ResourceNotFoundError

credential = DefaultAzureCredential()

mg_client = ManagementGroupsAPI(credential)

for group in mg_client.entities.list():
    print(f"============ Group: {group.name}\t{group.display_name}\t{group.type}")
    print(group)
