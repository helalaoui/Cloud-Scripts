import boto3

regions = [
    "ca-central-1"
]

root_account = "0000000000"

accounts = {
    "111111111111": "default",
}

for region in regions:
    for account_id, account_name in accounts.items():
        print('='*30 + f"Account {account_name} ({account_id})")
        session = boto3.session.Session(profile_name=account_name, region_name=region)
        client = session.client('resourcegroupstaggingapi')

        response = client.get_resources(
            # TagFilters=[
            #     {
            #         'Key': 'Accelerator',
            #         'Values': [
            #             'AWSAccelerator',
            #         ]
            #     },
            # ],
            ResourcesPerPage=100,
            # ResourceTypeFilters=[
            #     'logs'
            # ]
        )
        
        for resource in response['ResourceTagMappingList']:
            print(resource['ResourceARN'])

