import hvac

# Environment variables for Vault
VAULT_ADDR = "http://127.0.0.1:8200"
VAULT_TOKEN = "hvs.xulUZkC7rMSNWFlYSFVmPmCa"

def retrieve_key_from_vault(username):
    # Initialize the Vault client
    client = hvac.Client(
        url=VAULT_ADDR,
        token=VAULT_TOKEN
    )
    
    if not client.is_authenticated():
        raise Exception("Vault authentication failed")

    # Construct the path to the secret
    secret_path = f"secret/data/{username}"
    
    try:
        # Read the secret from Vault
        secret_response = client.secrets.kv.read_secret_version(path=secret_path)
        secret_data = secret_response['data']['data']
        key = secret_data.get('key')

        if not key:
            raise Exception("Key not found in Vault response")
        
        return key

    except hvac.exceptions.InvalidPath:
        raise Exception(f"Secret path {secret_path} does not exist in Vault")

    except Exception as e:
        raise Exception(f"Error retrieving key from Vault: {e}")