from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import PolicyClient

# Acquire a credential object using CLI-based authentication.
credential = DefaultAzureCredential(exclude_shared_token_cache_credential=True)

