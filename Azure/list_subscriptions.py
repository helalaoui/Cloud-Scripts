from azure.identity import DefaultAzureCredential, AzureCliCredential
from azure.mgmt.resource import ResourceManagementClient, SubscriptionClient
from azure.mgmt.managementgroups import ManagementGroupsAPI
from azure.core.exceptions import ResourceNotFoundError

credential = DefaultAzureCredential()

sub_client = SubscriptionClient(credential)

for sub in sub_client.subscriptions.list():
    print(f"============ Subscription: {sub.name}\t{group.id}\t{sub.tenant_id}")
    print(sub)
