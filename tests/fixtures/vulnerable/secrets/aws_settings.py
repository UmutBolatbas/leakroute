# Fixture: tokens are generated at test time.
AWS_ACCESS_KEY_ID = "__AWS_KEY_ID__"  # expect: secret/aws-access-key-id
aws_secret_access_key = "__AWS_SECRET__"  # expect: secret/aws-secret-access-key
DB_PASSWORD = "__PASSWORD__"  # expect: secret/hardcoded-password
signing_key = '__HEX__'  # expect: secret/generic-high-entropy
