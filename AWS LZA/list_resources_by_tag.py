import boto3

regions = [
    "ca-central-1"
]

root_account = "11111111111"

accounts = {
    "1111111111": "default",
    "2222222222": "Journalisation",
}

for region in regions:
    for account_id, account_name in accounts.items():
        print('='*30 + f"Account {account_name} ({account_id})")
        session = boto3.session.Session(profile_name=account_name, region_name=region)
        client = session.client('resourcegroupstaggingapi')

        response = client.get_resources(
            TagFilters=[
                {
                    'Key': 'Accelerator',
                    'Values': [
                        'AWSAccelerator',
                    ]
                },
            ],
            ResourcesPerPage=100,
            # ResourceTypeFilters=[
            #     'logs'
            # ]
        )
        
        for resource in response['ResourceTagMappingList']:
            print(resource['ResourceARN'])

