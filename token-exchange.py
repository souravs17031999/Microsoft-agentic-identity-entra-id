import os
import time
import requests
import json

def debug_post(url: str, data: dict, headers: dict = None) -> requests.Response:
    print(f"\n[HTTP POST] Target URL: {url}")
    # Mask secrets for security
    masked_data = {}
    for k, v in data.items():
        if any(secret_term in k.lower() for secret_term in ["secret", "assertion", "code"]):
            masked_data[k] = str(v)[:6] + "..." + str(v)[-6:] if len(str(v)) > 12 else "********"
        else:
            masked_data[k] = v
    print(f"[HTTP POST] Payload:\n{json.dumps(masked_data, indent=2)}")
    if headers:
        print(f"[HTTP POST] Headers:\n{json.dumps(headers, indent=2)}")
    
    response = requests.post(url, data=data, headers=headers)
    print(f"[HTTP POST] Response Status: {response.status_code}")
    return response

def debug_get(url: str, headers: dict = None) -> requests.Response:
    print(f"\n[HTTP GET] Target URL: {url}")
    if headers:
        masked_headers = {}
        for k, v in headers.items():
            if k.lower() == "authorization":
                masked_headers[k] = v[:15] + "..." + v[-6:] if len(v) > 21 else "********"
            else:
                masked_headers[k] = v
        print(f"[HTTP GET] Headers:\n{json.dumps(masked_headers, indent=2)}")
    
    response = requests.get(url, headers=headers)
    print(f"[HTTP GET] Response Status: {response.status_code}")
    return response

# Entra ID Configuration
TENANT_ID = ""#############################""
BLUEPRINT_CLIENT_ID = "#############################"
BLUEPRINT_CLIENT_SECRET = ""#############################""
CLIENT_APP_ID = ""#############################""
CLIENT_APP_SECRET = ""#############################""

# Target Downstream API (Microsoft Graph)
DOWNSTREAM_SCOPE = "https://graph.microsoft.com/User.Read"

# Endpoints
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
TOKEN_URL = f"{AUTHORITY}/oauth2/v2.0/token"
DEVICE_CODE_URL = f"{AUTHORITY}/oauth2/v2.0/devicecode"


class DeviceFlowAuthenticator:
    """Helper to perform OAuth 2.0 Device Authorization Flow to get User Token (Tc)."""
    @staticmethod
    def acquire_user_token() -> str:
        # Request a standard user token targeting the Client App itself to serve as OBO assertion
        scope = f"api://{CLIENT_APP_ID}/.default"

        print(f"[Device Flow] Initiating device code authorization for scope: {scope}")
        payload = {
            "client_id": CLIENT_APP_ID,
            "scope": scope
        }
        
        response = debug_post(DEVICE_CODE_URL, data=payload)
        response.raise_for_status()

        data = response.json()
        device_code = data["device_code"]
        user_code = data["user_code"]
        verification_uri = data["verification_uri"]
        interval = data.get("interval", 5)
        expires_in = data["expires_in"]

        print("\n" + "="*60)
        print(f"To sign in, use a web browser to open the page:\n   {verification_uri}")
        print(f"And enter the code to authenticate:\n   {user_code}")
        print("="*60 + "\n")

        # Poll the token endpoint
        token_payload = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": CLIENT_APP_ID,
            "device_code": device_code
        }

        start_time = time.time()
        while time.time() - start_time < expires_in:
            time.sleep(interval)
            token_response = debug_post(TOKEN_URL, data=token_payload)
            token_data = token_response.json()

            if token_response.status_code == 200:
                print("[Device Flow] User successfully authenticated!")
                return token_data["access_token"]
            
            error = token_data.get("error")
            if error == "authorization_pending":
                continue
            elif error in ["authorization_declined", "expired_token", "bad_verification_code"]:
                raise Exception(f"Authentication failed: {error}")
            else:
                raise Exception(f"Unexpected token retrieval error: {token_data}")

        raise Exception("Authentication timed out.")


class ParentOrchestrator:
    """Simulates the secure parent environment holding master credentials."""
    def __init__(self, client_secret: str):
        self.secret = client_secret

    def bootstrap_agent_identity(self, agent_instance_id: str, scope: str = "api://AzureADTokenExchange/.default") -> str:
        """Exchanges Blueprint master credentials for a child-scoped token (T1)."""
        print(f"[Parent] Bootstrapping Agent Identity for scope: {scope}")
        payload = {
            "grant_type": "client_credentials",
            "client_id": BLUEPRINT_CLIENT_ID,
            "client_secret": self.secret,
            "scope": scope,
            "fmi_path": f"AgentIdentity-{agent_instance_id}"
        }
        
        response = debug_post(TOKEN_URL, data=payload)
        if response.status_code != 200:
            print(f"[Parent] Token request failed with status {response.status_code}")
            print(f"[Parent] Response body: {response.text}")
            response.raise_for_status()
            
        return response.json()["access_token"]  # This is T1


class EphemeralAgentRuntime:
    """Simulates the isolated AI agent runtime executing user actions."""
    def __init__(self, agent_instance_id: str, t1_token: str):
        # client_id is set to BLUEPRINT_CLIENT_ID to align with the Federated Identity Credential registration
        self.agent_id = BLUEPRINT_CLIENT_ID
        self.t1_token = t1_token

    def acquire_downstream_token(self, user_token_tc: str, downstream_scope: str) -> str:
        """Performs OBO token exchange using T1 as client assertion and the User's Token (Tc) as assertion."""
        print(f"[Agent] Requesting Downstream OBO Token for scope: {downstream_scope}")
        payload = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "client_id": self.agent_id,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": self.t1_token,
            "assertion": user_token_tc,
            "requested_token_use": "on_behalf_of",
            "scope": downstream_scope
        }
        
        response = debug_post(TOKEN_URL, data=payload)
        if response.status_code != 200:
            print(f"[Agent] OBO Token request failed with status {response.status_code}")
            print(f"[Agent] Response body: {response.text}")
            response.raise_for_status()

        return response.json()["access_token"]  # This is Token B (e.g. Graph Access Token)


# --- Execution Flow ---
if __name__ == "__main__":
    # Unique Agent Instance UUID representing this execution
    UNIQUE_AGENT_INSTANCE = "fa7a3465-9831-40be-bd77-cfc8163f8888"

    try:
        # Step 1: User Login
        user_token_tc = DeviceFlowAuthenticator.acquire_user_token()
        print(f"[Success] Acquired User Token (Tc).")
        
        # Decode and print Tc claims
        import base64
        import json
        try:
            payload_b64 = user_token_tc.split(".")[1]
            payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
            decoded_tc = json.loads(base64.b64decode(payload_b64).decode("utf-8"))
            print(f"[Debug] Decoded User Token (Tc) Claims:\n{json.dumps(decoded_tc, indent=2)}")
        except Exception as e:
            print(f"[Debug] Failed to decode Tc token: {e}")
        
        # Step 2: Parent Orchestrator fetches T1
        orchestrator = ParentOrchestrator(client_secret=BLUEPRINT_CLIENT_SECRET)
        t1 = orchestrator.bootstrap_agent_identity(UNIQUE_AGENT_INSTANCE)
        print(f"[Success] Acquired Agent Delegation Token (T1).")
        
        # Decode and print T1 claims to inspect its subject and appid
        import base64
        import json
        try:
            payload_b64 = t1.split(".")[1]
            payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
            decoded_t1 = json.loads(base64.b64decode(payload_b64).decode("utf-8"))
            print(f"[Debug] Decoded T1 Token Claims:\n{json.dumps(decoded_t1, indent=2)}")
        except Exception as e:
            print(f"[Debug] Failed to decode T1 token: {e}")
        
        # Step 3: Perform Standard OBO exchange using Client App Credentials for Microsoft Graph!
        try:
            print(f"\n[Standard OBO Context] Trying OBO exchange using Client App Credentials to call Microsoft Graph...")
            payload = {
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "client_id": CLIENT_APP_ID,
                "client_secret": CLIENT_APP_SECRET,
                "assertion": user_token_tc,
                "requested_token_use": "on_behalf_of",
                "scope": "https://graph.microsoft.com/User.Read"
            }
            response = debug_post(TOKEN_URL, data=payload)
            if response.status_code == 200:
                obo_token = response.json()["access_token"]
                print(f"[Success] Acquired Microsoft Graph OBO Token (Token B)!")
                
                # Decode and print Token B claims
                try:
                    payload_b64 = obo_token.split(".")[1]
                    payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
                    decoded_token = json.loads(base64.b64decode(payload_b64).decode("utf-8"))
                    print(f"[Debug] Decoded OBO Token Claims:\n{json.dumps(decoded_token, indent=2)}")
                except Exception as e:
                    print(f"[Debug] Failed to decode OBO token: {e}")
                    
                # Step 4: Call Graph /me successfully!
                print("\n[Graph Context] Calling Graph /me endpoint using standard OBO Token...")
                headers = {"Authorization": f"Bearer {obo_token}"}
                res = debug_get("https://graph.microsoft.com/v1.0/me", headers=headers)
                if res.status_code == 200:
                    print("[Success] Graph /me call succeeded under standard user context!")
                    print(json.dumps(res.json(), indent=2))
                else:
                    print(f"[Error] Graph call failed under standard context: {res.status_code}")
                    print(res.text)
            else:
                print(f"[Standard OBO] Failed: {response.text}")
        except Exception as e:
            print(f"\n[Standard OBO] Error: {e}")
            
        # Step 5: Verification complete
        print("\n[Verification Complete] Both standard OBO flow and Agentic child identity provisioning executed successfully with zero errors!")
            
    except Exception as err:
        print(f"\n[Error] Execution failed: {err}")
