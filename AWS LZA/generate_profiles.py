accounts = {
    "222222222222": "Journalisation",
    "111111111111": "Securite",
}

for account_id, account_name in accounts.items():
    print(f"[profile {account_name}]\nrole_arn = arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole\ncredential_source = EcsContainer\n\n")
    

