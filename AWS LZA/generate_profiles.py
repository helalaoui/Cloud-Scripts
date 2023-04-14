accounts = {
    "721601628576": "ROOTTACT",
    "139085432331": "Journalisation",
    "126235163086": "Securite",
    "402618278777": "Operations",
    "198267348705": "Perimetre",
    "861610412706": "Reseautique",
    "988042271473": "Dev1",
    "384265717064": "Prod1",
    "973746865003": "CarredeSable1"
}

for account_id, account_name in accounts.items():
    print(f"[profile {account_name}]\nrole_arn = arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole\ncredential_source = EcsContainer\n\n")
    

