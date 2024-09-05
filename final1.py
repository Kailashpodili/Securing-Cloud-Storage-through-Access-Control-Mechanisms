import tkinter as tk
from tkinter import ttk, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import dropbox
import json
import io
import datetime
from typing import Dict
DROPBOX_ACCESS_TOKEN = "REPLACE_YOUR_TOKEN_KEY"


dbx = dropbox.Dropbox(DROPBOX_ACCESS_TOKEN)


user_data_dict: Dict[str, Dict[str, str]] = {}

def create_table_if_not_exists():
    global user_data_dict
    user_data_dict = {}

def generate_rsa_keypair(key_length=1024):
    key = RSA.generate(key_length)
    public_key = key.publickey().export_key().decode()
    private_key = key.export_key().decode()
    return public_key, private_key

def rsa_encrypt(public_key, plaintext):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return ciphertext

def rsa_decrypt(private_key, ciphertext):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    decrypted_text = cipher.decrypt(ciphertext)
    return decrypted_text.decode()

def upload_user_data_to_dropbox():
    global user_data_dict
    try:
        # Convert datetime objects to strings
        user_data_dict_serializable = {}
        for username, user_data in user_data_dict.items():
            user_data_serializable = user_data.copy()
            if isinstance(user_data.get('approved_time'), datetime.datetime):
                user_data_serializable['approved_time'] = user_data['approved_time'].isoformat()
            user_data_serializable['login_attempts'] = [str(attempt) for attempt in user_data.get('login_attempts', [])]
            user_data_serializable['logout_attempts'] = [str(attempt) for attempt in user_data.get('logout_attempts', [])]
            user_data_dict_serializable[username] = user_data_serializable

        data = json.dumps(user_data_dict_serializable)
        with io.BytesIO(data.encode()) as stream:
            dbx.files_upload(stream.read(), '/user_data.json', mode=dropbox.files.WriteMode('overwrite'))
        print("User data uploaded to Dropbox successfully.")
    except dropbox.exceptions.ApiError as e:
        print(f"Error uploading user data to Dropbox: {e}")


def download_user_data_from_dropbox():
    global user_data_dict
    try:
        metadata, response = dbx.files_download('/user_data.json')
        data = response.content.decode()
        user_data_dict = json.loads(data)
        print("User data downloaded from Dropbox successfully.")
    except dropbox.exceptions.ApiError as e:
        if isinstance(e.error, dropbox.files.DownloadError) and e.error.is_path() and e.error.get_path().is_not_found():
            print("File not found. Initializing empty user data dictionary.")
            user_data_dict = {}
            upload_user_data_to_dropbox()  # Create the file in Dropbox with an empty dictionary
        else:
            print(f"Error downloading user data from Dropbox: {e}")

def register_user(username, password, role):
    global user_data_dict

    if username in user_data_dict:
        messagebox.showerror("Error", "Username already exists. Please choose a different username.")
        return False

    approved = (role == 'manager')  # Managers are automatically approved, customers require approval

    # Generate RSA key pair
    public_key, private_key = generate_rsa_keypair()

    # Store user data in memory
    user_data_dict[username] = {
        'password': password,
        'role': role,
        'approved': approved,
        'approved_time': datetime.datetime.now() if approved else None,
        'login_attempts': [],
        'logout_attempts': [],
        'public_key': public_key,
        'private_key': private_key,
        'data_from_manager': []  # Changed to store a list of data
    }

    # Store user data in Dropbox
    upload_user_data_to_dropbox()

    messagebox.showinfo("Success", "User registered successfully.")
    return True

def login(username, password):
    global user_data_dict

    if username not in user_data_dict:
        messagebox.showerror("Error", "Invalid username. Login unsuccessful.")
        return None

    user_data = user_data_dict[username]

    if user_data['role'] == 'customer' and not user_data['approved']:
        messagebox.showerror("Error", "Customer login requires manager approval. Please wait for approval.")
        return None

    if password != user_data['password']:
        messagebox.showerror("Error", "Invalid password. Login unsuccessful.")
        return None

    user_data['login_attempts'].append(str(datetime.datetime.now()))
    upload_user_data_to_dropbox()
    messagebox.showinfo("Success", "Login successful.")
    return user_data

def logout(username):
    global user_data_dict
    if username in user_data_dict:
        user_data_dict[username]['logout_attempts'].append(str(datetime.datetime.now()))
        upload_user_data_to_dropbox()
        messagebox.showinfo("Success", "Logout successful.")
    else:
        messagebox.showerror("Error", "Invalid username. Logout unsuccessful.")

def approve_customer(username):
    global user_data_dict

    if username not in user_data_dict:
        messagebox.showerror("Error", "Customer not found.")
        return

    user_data_dict[username]['approved'] = True
    user_data_dict[username]['approved_time'] = datetime.datetime.now()
    upload_user_data_to_dropbox()
    messagebox.showinfo("Success", "Customer approved successfully.")

def send_data_to_customer(manager_username, customer_username, data):
    global user_data_dict

    if customer_username not in user_data_dict:
        messagebox.showerror("Error", "Customer not found.")
        return

    if user_data_dict[manager_username]['role'] != 'manager':
        messagebox.showerror("Error", "Only managers can send data.")
        return

    user_data_dict[customer_username]['data_from_manager'].append(data)  # Append data to the list
    upload_user_data_to_dropbox()
    messagebox.showinfo("Success", "Data sent to customer successfully.")

def view_login_details():
    details_window = tk.Toplevel()
    details_window.title("Login and Logout Details")

    # Create a treeview to list all customers
    tree_details = ttk.Treeview(details_window, columns=("username"), show='headings')
    tree_details.heading("username", text="Username")
    tree_details.pack(pady=10, fill='both', expand=True)

    # Create a frame to hold login/logout details for selected username
    details_frame = ttk.Frame(details_window)
    details_frame.pack(pady=10, fill='both', expand=True)

    # Username label and selected username variable
    selected_username = tk.StringVar()

    def on_select(event):
        selected = tree_details.selection()
        if selected:
            username = tree_details.item(selected[0], 'values')[0]
            selected_username.set(username)
            display_login_logout_details(username)

    tree_details.bind('<<TreeviewSelect>>', on_select)

    def display_login_logout_details(username):
        # Clear previous details
        for widget in details_frame.winfo_children():
            widget.destroy()

        # Get user data
        user_data = user_data_dict.get(username, {})
        login_attempts = user_data.get('login_attempts', [])
        logout_attempts = user_data.get('logout_attempts', [])

        ttk.Label(details_frame, text=f"Username: {username}").grid(row=0, column=0, pady=5, sticky="w")
        ttk.Label(details_frame, text=f"Approved Time: {user_data.get('approved_time', 'Not approved yet')}").grid(row=1, column=0, pady=5, sticky="w")

        # Display login attempts
        ttk.Label(details_frame, text="Login Attempts:").grid(row=2, column=0, pady=5, sticky="w")
        login_text = tk.Text(details_frame, height=5, width=50)
        login_text.grid(row=3, column=0, pady=5, sticky="w")
        login_text.insert(tk.END, '\n'.join(login_attempts) if login_attempts else "No login attempts")

        # Display logout attempts
        ttk.Label(details_frame, text="Logout Attempts:").grid(row=4, column=0, pady=5, sticky="w")
        logout_text = tk.Text(details_frame, height=5, width=50)
        logout_text.grid(row=5, column=0, pady=5, sticky="w")
        logout_text.insert(tk.END, '\n'.join(logout_attempts) if logout_attempts else "No logout attempts")

    # Populate treeview with customer usernames
    for username, data in user_data_dict.items():
        if data['role'] == 'customer':
            tree_details.insert("", "end", values=(username,))

class UserInterface:
    def __init__(self, root):
        self.root = root
        self.root.title("User Management System")

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(pady=10, expand=True)

        self.frame_login = ttk.Frame(self.notebook, width=400, height=300)
        self.frame_login.pack(fill='both', expand=True)
        self.frame_register = ttk.Frame(self.notebook, width=400, height=300)
        self.frame_register.pack(fill='both', expand=True)
        self.frame_manager = ttk.Frame(self.notebook, width=400, height=300)
        self.frame_manager.pack(fill='both', expand=True)
        self.frame_customer = ttk.Frame(self.notebook, width=400, height=300)
        self.frame_customer.pack(fill='both', expand=True)

        self.notebook.add(self.frame_login, text='Login')
        self.notebook.add(self.frame_register, text='Register')
        self.notebook.add(self.frame_manager, text='Manager')
        self.notebook.add(self.frame_customer, text='Customer')

        self.create_login_widgets()
        self.create_register_widgets()
        self.create_manager_widgets()
        self.create_customer_widgets()

    def create_login_widgets(self):
        self.label_username = ttk.Label(self.frame_login, text="Username:")
        self.label_username.pack(pady=5)
        self.entry_username = ttk.Entry(self.frame_login)
        self.entry_username.pack(pady=5)

        self.label_password = ttk.Label(self.frame_login, text="Password:")
        self.label_password.pack(pady=5)
        self.entry_password = ttk.Entry(self.frame_login, show="*")
        self.entry_password.pack(pady=5)

        self.button_login = ttk.Button(self.frame_login, text="Login", command=self.handle_login)
        self.button_login.pack(pady=5)

        self.button_logout = ttk.Button(self.frame_login, text="Logout", command=self.handle_logout)
        self.button_logout.pack(pady=5)

    def create_register_widgets(self):
        self.label_reg_username = ttk.Label(self.frame_register, text="Username:")
        self.label_reg_username.pack(pady=5)
        self.entry_reg_username = ttk.Entry(self.frame_register)
        self.entry_reg_username.pack(pady=5)

        self.label_reg_password = ttk.Label(self.frame_register, text="Password:")
        self.label_reg_password.pack(pady=5)
        self.entry_reg_password = ttk.Entry(self.frame_register, show="*")
        self.entry_reg_password.pack(pady=5)

        self.label_reg_role = ttk.Label(self.frame_register, text="Role:")
        self.label_reg_role.pack(pady=5)
        self.combo_reg_role = ttk.Combobox(self.frame_register, values=["manager", "customer"])
        self.combo_reg_role.pack(pady=5)

        self.button_register = ttk.Button(self.frame_register, text="Register", command=self.handle_register)
        self.button_register.pack(pady=5)

    def create_manager_widgets(self):
        self.label_manager_info = ttk.Label(self.frame_manager, text="Manager Actions")
        self.label_manager_info.pack(pady=5)

        self.button_refresh_customers = ttk.Button(self.frame_manager, text="Refresh Customer List", command=self.show_customers)
        self.button_refresh_customers.pack(pady=5)

        # Treeview to list customers
        self.tree_customers = ttk.Treeview(self.frame_manager, columns=("username", "approved", "approved_time"), show='headings', selectmode='browse')
        self.tree_customers.heading("username", text="Username")
        self.tree_customers.heading("approved", text="Approved")
        self.tree_customers.heading("approved_time", text="Approved Time")
        self.tree_customers.pack(pady=5, fill='both', expand=True)

        self.tree_customers.bind("<<TreeviewSelect>>", self.on_customer_select)

        # Button to approve selected customer
        self.button_approve_customer = ttk.Button(self.frame_manager, text="Approve Selected Customer", command=self.handle_approve_selected_customer)
        self.button_approve_customer.pack(pady=5)

        # Button to send data to selected customer
        self.button_send_data = ttk.Button(self.frame_manager, text="Send Data to Selected Customer", command=self.handle_send_data)
        self.button_send_data.pack(pady=5)

        self.label_data_to_send = ttk.Label(self.frame_manager, text="Data:")
        self.label_data_to_send.pack(pady=5)
        self.entry_data_to_send = ttk.Entry(self.frame_manager)
        self.entry_data_to_send.pack(pady=5)

        self.button_view_details = ttk.Button(self.frame_manager, text="View Login/Logout Details", command=self.handle_view_details)
        self.button_view_details.pack(pady=5)

        # Label to show approval time of selected customer
        self.label_approval_time = ttk.Label(self.frame_manager, text="Approval Time:")
        self.label_approval_time.pack(pady=5)
        self.label_approval_time_value = ttk.Label(self.frame_manager, text="No customer selected")
        self.label_approval_time_value.pack(pady=5)

        # Treeview to display sent data history
        self.tree_data_history = ttk.Treeview(self.frame_manager, columns=("username", "data"), show='headings', selectmode='browse')
        self.tree_data_history.heading("username", text="Username")
        self.tree_data_history.heading("data", text="Sent Data")
        self.tree_data_history.pack(pady=5, fill='both', expand=True)

    def create_customer_widgets(self):
        self.label_customer_info = ttk.Label(self.frame_customer, text="Customer Info")
        self.label_customer_info.pack(pady=5)

        self.label_received_data = ttk.Label(self.frame_customer, text="Received Data:")
        self.label_received_data.pack(pady=5)
        self.text_received_data = tk.Text(self.frame_customer, height=10, width=40)
        self.text_received_data.pack(pady=5)

    def handle_login(self):
        username = self.entry_username.get()
        password = self.entry_password.get()

        user_data = login(username, password)
        if user_data:
            if user_data['role'] == 'manager':
                self.notebook.select(self.frame_manager)
                self.show_customers()
                self.show_sent_data_history()
            elif user_data['role'] == 'customer':
                self.notebook.select(self.frame_customer)
                self.text_received_data.delete("1.0", tk.END)
                # Display all received data
                self.text_received_data.insert(tk.END, '\n'.join(user_data['data_from_manager']))

    def handle_logout(self):
        username = self.entry_username.get()
        logout(username)

    def handle_register(self):
        username = self.entry_reg_username.get()
        password = self.entry_reg_password.get()
        role = self.combo_reg_role.get()

        register_user(username, password, role)

    def handle_approve_selected_customer(self):
        selected_item = self.tree_customers.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "No customer selected.")
            return

        selected_username = self.tree_customers.item(selected_item[0], 'values')[0]
        approve_customer(selected_username)
        self.show_customers()

    def handle_send_data(self):
        selected_item = self.tree_customers.selection()
        if selected_item:
            customer_username = self.tree_customers.item(selected_item[0], 'values')[0]
            data = self.entry_data_to_send.get()

            send_data_to_customer(self.entry_username.get(), customer_username, data)
            self.entry_data_to_send.delete(0, tk.END)  # Clear the entry box after sending data
            self.show_sent_data_history()  # Refresh data history view
        else:
            messagebox.showerror("Error", "No customer selected.")

    def handle_view_details(self):
        view_login_details()

    def show_customers(self):
        for row in self.tree_customers.get_children():
            self.tree_customers.delete(row)
        for username, data in user_data_dict.items():
            if data['role'] == 'customer':
                self.tree_customers.insert("", "end", values=(
                    username, data['approved'], data.get('approved_time', "Not approved yet")
                ))

    def show_sent_data_history(self):
        for row in self.tree_data_history.get_children():
            self.tree_data_history.delete(row)
        selected_item = self.tree_customers.selection()
        if selected_item:
            customer_username = self.tree_customers.item(selected_item[0], 'values')[0]
            data_list = user_data_dict.get(customer_username, {}).get('data_from_manager', [])
            for data in data_list:
                self.tree_data_history.insert("", "end", values=(customer_username, data))

    def on_customer_select(self, event):
        selected_item = self.tree_customers.selection()
        if selected_item:
            username = self.tree_customers.item(selected_item[0], 'values')[0]
            self.label_approval_time_value.config(text=user_data_dict.get(username, {}).get('approved_time', "Not approved yet"))

if __name__ == "__main__":
    root = tk.Tk()
    create_table_if_not_exists()
    download_user_data_from_dropbox()
    app = UserInterface(root)
    root.mainloop()

