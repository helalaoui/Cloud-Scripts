from azure.identity import DefaultAzureCredential, AzureCliCredential, InteractiveBrowserCredential, SharedTokenCacheCredential
from azure.mgmt.resource import ResourceManagementClient, SubscriptionClient
from azure.mgmt.managementgroups import ManagementGroupsAPI
from azure.core.exceptions import ResourceNotFoundError

credential = DefaultAzureCredential(exclude_shared_token_cache_credential=True)

# credential = DefaultAzureCredential(
#     exclude_workload_identity_credential=True,
#     exclude_developer_cli_credential=True,
#     exclude_cli_credential=False,
#     exclude_environment_credential=True,
#     exclude_managed_identity_credential=True,
#     exclude_powershell_credential=True,
#     exclude_visual_studio_code_credential=True,
#     exclude_shared_token_cache_credential=True,
#     exclude_interactive_browser_credential=True,
# )

sub_client = SubscriptionClient(credential)

for sub in sub_client.subscriptions.list():
    print(f"============ Subscription: {sub.display_name}\t{sub.subscription_id}")
    #print(sub)
