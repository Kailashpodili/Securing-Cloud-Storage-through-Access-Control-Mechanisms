import dropbox
import json


DROPBOX_ACCESS_TOKEN = "REPLACE_YOUR_TOKEN_KEY"
dbx = dropbox.Dropbox(DROPBOX_ACCESS_TOKEN)

def download_user_data_from_dropbox():
    """Download user data from Dropbox and return as a dictionary."""
    try:
        metadata, response = dbx.files_download('/user_data.json')
        data = response.content.decode()
        user_data_dict = json.loads(data)
        print("User data downloaded successfully.")
        return user_data_dict
    except dropbox.exceptions.ApiError as e:
        print(f"Error downloading user data from Dropbox: {e}")
        return {}

def display_user_data(user_data_dict):
    """Display user data in a structured format."""
    for username, data in user_data_dict.items():
        print(f"\nUsername: {username}")
        print(f"  Role: {data['role']}")
        print(f"  Approved: {data['approved']}")
        print(f"  Password: {data['password']}")
        print(f"  Public Key: {data['public_key']}")
        print(f"  Private Key: {data['private_key']}")
        
        data_from_manager = data.get('data_from_manager', 'No data received')
        print(f"  Data from Manager: {data_from_manager}")
        print("  Login Attempts:")
        for attempt in data['login_attempts']:
            print(f"    - {attempt}")
        print("  Logout Attempts:")
        for attempt in data['logout_attempts']:
            print(f"    - {attempt}")
        print("\n")

# Download and display the user data
user_data_dict = download_user_data_from_dropbox()
display_user_data(user_data_dict)
