import requests
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from tkinter import *
from tkinter import Tk, Label, Button, messagebox, filedialog, PhotoImage, ttk
from threading import Thread
import threading
import socket
import os
import time
import psutil
import sqlite3
import bcrypt



host = 'localhost'  # Localhost
port = 8083         # Port to listen on (make sure this matches what you're using in your script)

# Step 2: Create the server_socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Step 3: Set the socket options (This line must come after the server_socket is defined)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Step 4: Bind the socket to address and port
server_socket.bind((host, port))

# Step 5: Start listening on the socket
server_socket.listen()
print(f"Listening on {host}:{port}")

os.environ['HTTP_PROXY'] = 'http://localhost:8082/'
os.environ['HTTPS_PROXY'] = 'http://localhost:8082/'

#OAuth configuration
CLIENT_ID = '286423736838-6viplrjfu7hdp58grborrqjoeu7q4uek.apps.googleusercontent.com'
CLIENT_SECRET = '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'
SCOPES = ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email']




# Create a dictionary to store username-password pairs (for demonstration purposes)
user_credentials = {}

# Create a list to store the logged-in users
logged_in_users = []


root=Tk()
root.title("Pylink")
root.geometry("450x560+500+200")
root.configure(bg="#f4fdfe")
root.resizable(False,False)


# Define the style for the ttk buttons for a more modern look
style = ttk.Style()
style.configure('TButton', padding=6, relief="flat", background="#ccc")


# Status Label for displaying messages
status_label = Label(root, text="Status: Idle", bg="#f4fdfe", font=('Arial', 12))
status_label.pack()


def init_db():
    conn = sqlite3.connect('pylink.db')
    c = conn.cursor()
    # Existing users table creation
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT NOT NULL UNIQUE,
                 password TEXT NOT NULL)''')
    # Sessions table creation
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER NOT NULL,
                 logged_in TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                 FOREIGN KEY(user_id) REFERENCES users(id))''')
    conn.commit()
    conn.close()

# Call init_db at the start of your application (e.g., before the GUI is initialized)
init_db()

# At the beginning of your script, after importing modules and before defining functions
current_user_username = None  # This will store the username of the logged-in user



def get_resource_usage():
    global cpu_usage, ram_usage_mb
    cpu_usage = psutil.cpu_percent(interval=None)

    # Get the memory usage of the current process
    process = psutil.Process(os.getpid())
    ram_usage_mb = process.memory_info().rss / (1024 ** 2)  # Convert bytes to MB for the current process

    # Update the progress bars and labels with the values from the global variables
    cpu_progress['value'] = cpu_usage
    ram_progress['value'] = (ram_usage_mb / (psutil.virtual_memory().total / (1024 ** 2))) * 100
    cpu_label.config(text=f"CPU Usage: {cpu_usage}%")
    ram_label.config(text=f"App RAM Usage: {ram_usage_mb:.2f} MB")

    # Schedule the function to be called again after 1000 milliseconds
    root.after(1000, get_resource_usage)


# Function to display the list of logged-in users
def show_logged_in_users():
    users_window = Toplevel(root)
    users_window.title("Logged In Users")
    users_window.geometry("200x300")

    users_label = Label(users_window, text="Logged In Users", font=("Arial", 14, "bold"))
    users_label.pack()

    # Create a Listbox to display usernames
    users_listbox = Listbox(users_window, selectmode="single")
    users_listbox.pack(fill="both", expand=True)

    # Add logged-in users to the Listbox
    for user in logged_in_users:
        users_listbox.insert(END, user)



def login():
    global login_window
    # Create a login window
    login_window = Toplevel(root)
    login_window.title("Login")
    login_window.geometry("300x200")

    # Create login widgets
    global username_entry
    global password_entry

    username_label = Label(login_window, text="Username:")
    username_label.pack()
    username_entry = Entry(login_window)
    username_entry.pack()

    password_label = Label(login_window, text="Password:")
    password_label.pack()
    password_entry = Entry(login_window, show="*")  # Password input
    password_entry.pack()

    login_button = Button(login_window, text="Login", command=perform_login)
    login_button.pack()

def register():
    global register_window
    # Create a registration window
    register_window = Toplevel(root)
    register_window.title("Register")
    register_window.geometry("300x200")

    # Create registration widgets
    global new_username_entry
    global new_password_entry

    new_username_label = Label(register_window, text="New Username:")
    new_username_label.pack()
    new_username_entry = Entry(register_window)
    new_username_entry.pack()

    new_password_label = Label(register_window, text="New Password:")
    new_password_label.pack()
    new_password_entry = Entry(register_window, show="*")  # Password input
    new_password_entry.pack()

    register_button = Button(register_window, text="Register", command=perform_registration)
    register_button.pack()

# Define functions to perform login and registration
def perform_login():
    username = username_entry.get()
    password = password_entry.get().encode('utf-8')
    conn = sqlite3.connect('pylink.db')
    c = conn.cursor()
    # Fetch the hashed password for the given username
    c.execute("SELECT id, password FROM users WHERE username=?", (username,))
    user = c.fetchone()
    if user and bcrypt.checkpw(password, user[1].encode('utf-8')):
        global current_user_username
        current_user_username = username  # Update the current user's username
        update_logged_in_user_display()  # Update the UI to show the current user
        messagebox.showinfo("Login Successful", "You have successfully logged in.")
        login_window.destroy()
    else:
        messagebox.showerror("Login Failed", "Invalid username or password.")
    conn.close()



def perform_logout():
    global current_user_id
    if current_user_id is not None:
        conn = sqlite3.connect('pylink.db')
        c = conn.cursor()
        c.execute("DELETE FROM sessions WHERE user_id=?", (current_user_id,))
        conn.commit()
        conn.close()
        messagebox.showinfo("Logout Successful", "You have been logged out.")
        current_user_id = None  # Reset the current user ID after logout
        # Update UI to reflect the logout
    else:
        messagebox.showerror("Logout Failed", "No user is currently logged in.")

def logout():
    global current_user_username
    if current_user_username:
        # Assuming you want to delete the session from the database, you would need the user's ID.
        # Since we're working with the username, let's fetch the user ID first (add this if you're tracking sessions in DB).
        conn = sqlite3.connect('pylink.db')
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username=?", (current_user_username,))
        user_id = c.fetchone()
        if user_id:
            c.execute("DELETE FROM sessions WHERE user_id=?", (user_id[0],))
            conn.commit()

        current_user_username = None  # Clear the current user's username
        update_logged_in_user_display()  # Update the UI to reflect no user logged in
        messagebox.showinfo("Logout Successful", "You have been logged out.")
        conn.close()
    else:
        messagebox.showerror("Logout Failed", "No user is currently logged in.")



def update_logged_in_user_display():
    if current_user_username:
        logged_in_user_label.config(text=f"Wellcome: {current_user_username}")
        logout_button.pack()  # Make logout button visible
    else:
        logged_in_user_label.config(text="No user logged in")
        logout_button.pack_forget()  # Hide logout button




def show_logged_in_users():
    conn = sqlite3.connect('pylink.db')
    c = conn.cursor()
    c.execute('''SELECT users.username FROM users
                 INNER JOIN sessions ON users.id = sessions.user_id''')
    logged_in_users = c.fetchall()
    users_window = Toplevel(root)
    users_window.title("Logged In Users")
    users_window.geometry("200x300")
    users_label = Label(users_window, text="Logged In Users", font=("Arial", 14, "bold"))
    users_label.pack()
    users_listbox = Listbox(users_window, selectmode="single")
    users_listbox.pack(fill="both", expand=True)
    for user in logged_in_users:
        users_listbox.insert(END, user[0])
    conn.close()


def perform_registration():
    new_username = new_username_entry.get()
    new_password = new_password_entry.get().encode('utf-8')  # Encode the password to bytes

    # Generate the hashed password
    hashed_password = bcrypt.hashpw(new_password, bcrypt.gensalt())

    # Connect to the database
    conn = sqlite3.connect('pylink.db')
    c = conn.cursor()

    # Check if the username already exists
    c.execute("SELECT * FROM users WHERE username=?", (new_username,))
    if c.fetchone():
        messagebox.showerror("Registration Failed", "Username already exists.")
    else:
        # Insert the new user into the database with the hashed password
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (new_username, hashed_password.decode('utf-8')))
        conn.commit()
        messagebox.showinfo("Registration Successful", "You have successfully registered.")

    # Close the connection
    conn.close()
    register_window.destroy()




def start_oauth():
    flow = InstalledAppFlow.from_client_secrets_file(
        'client_secret.json', scopes=SCOPES)
    creds = flow.run_local_server(port=0)

    # user's access and refresh tokens
    # credentials to access Google APIs or your own backend

    # user profile information
    response = requests.get(
        'https://www.googleapis.com/oauth2/v1/userinfo',
        params={'access_token': creds.token})
    user_info = response.json()

    # user's email in a message box (or use as needed)
    messagebox.showinfo("User Info", f"Email: {user_info['email']}")

    return creds  # Return the creds object

def on_login_button_clicked():
    # Call function when the login button is clicked
    try:
        creds = start_oauth()  # Store the returned creds in a variable
        # creds here or pass it to other functions as needed
    except Exception as e:
        messagebox.showerror("Login Error", str(e))
        pass

def update_status(message):
    status_label.config(text=f"Status: {message}")

def Send():
    window  = Toplevel(root)
    window.title("Send")
    window.geometry('450x560+500+200')
    window.configure(bg="#f4fdfe")
    window.resizable(False,False)

    progress = ttk.Progressbar(window, orient=HORIZONTAL, length=100, mode='determinate')
    progress.pack()

    speed_label = Label(window, text="Speed: 0 KB/s", bg="#f4fdfe")
    speed_label.pack()


    def update_gui_from_thread(message):
        root.after(0, update_status, message)

    def select_file():
	    global filename
	    filename=filedialog.askopenfilename(initialdir=os.getcwd(),
                                        title='Select Image File',
                                        filetype=(('file_type', '*.txt'), ('all files', '*.*')))
    def sender():
        sender_thread = threading.Thread(target=threaded_sender)
        sender_thread.start()

    def threaded_sender():
        update_gui_from_thread("Setting up connection...")
        s = socket.socket()
        host = socket.gethostname()
        port = 8080

        try:
            s.bind((host, port))
            s.listen(1)
            update_gui_from_thread(f"Waiting for connections on {host}:{port}...")
            conn, addr = s.accept()
            update_gui_from_thread(f"Connected to {addr}")

            total_size = os.path.getsize(filename)
            conn.send(str(total_size).encode())
            bytes_sent = 0
            start_time = time.time()

            with open(filename, 'rb') as file:
                while True:
                    file_data = file.read(1024)
                    if not file_data:
                        break
                    conn.send(file_data)
                    bytes_sent += len(file_data)

                    # Update progress bar and speed in the GUI thread
                    root.after(0, lambda: progress.config(value=(bytes_sent / total_size) * 100))
                    elapsed_time = time.time() - start_time if time.time() - start_time > 0 else 1
                    speed = bytes_sent / elapsed_time / 1024  # Speed in KB/s
                    root.after(0, speed_label.config, text=f"Speed: {speed:.2f} KB/s")

        except Exception as e:
            update_gui_from_thread(f"Error: {e}")
        finally:
            s.close()
            update_gui_from_thread("Connection closed")


    #icon
    image_icon1=PhotoImage(file="Images/Send.png")
    window.iconphoto(False,image_icon1)
    Sbackground=PhotoImage(file="Images/Sender.png")
    Label(window,image=Sbackground).place(x=-2,y=0)

    Mbackground=PhotoImage(file="Images/id.png")
    Label(window,image=Mbackground,bg='#f4fdfe').place(x=60,y=280)

    host=socket.gethostname()
    Label(window,text=f'ID: {host}',bg='white',fg='black').place(x=140,y=290)


    Button(window,text="+ select file", width=10,height=1,font='arial 14 bold',bg="#fff",fg="#000",command=select_file).place(x=160,y=150)
    Button(window,text="SEND", width=8,height=1,font='arial 14 bold',bg='#000',fg="#fff",command=sender).place(x=300,y=150)
    window.mainloop()

def Receive():
    main=Toplevel(root)
    main.title("Receive")
    main.geometry('450x560+500+200')
    main.configure(bg="#f4fdfe")
    main.resizable(False,False)

    progress = ttk.Progressbar(main, orient=HORIZONTAL, length=100, mode='determinate')
    progress.pack()
    speed_label = Label(main, text="Speed: 0 KB/s", bg="#f4fdfe")
    speed_label.pack()

    def update_gui_from_thread(message):
        root.after(0, update_status, message)

    def receiver():
        receiver_thread = threading.Thread(target=threaded_receiver)
        receiver_thread.start()

    def threaded_receiver():
        update_gui_from_thread("Setting up connection...")
        ID = SenderID.get()
        filename1 = incoming_file.get()
        port = 8080

        if not filename1:
            update_gui_from_thread("Error: Please enter a filename.")
            return

        s = socket.socket()

        try:
            s.connect((ID, port))
            update_gui_from_thread(f"Connected to {ID}")

        # Logic to receive the file size from the sender
            total_size_str = s.recv(1024).decode()
            total_size = int(total_size_str)

            bytes_received = 0
            start_time = time.time()

            with open(filename1, 'wb') as file:
                while bytes_received < total_size:
                    file_data = s.recv(1024)
                    if not file_data:
                        break
                    file.write(file_data)
                    bytes_received += len(file_data)

                # Update progress bar and speed
                    root.after(0, lambda: progress.config(value=(bytes_received / total_size) * 100))
                    elapsed_time = time.time() - start_time if time.time() - start_time > 0 else 1
                    speed = bytes_received / elapsed_time / 1024  # Speed in KB/s
                    root.after(0, lambda: speed_label.config(text=f"Speed: {speed:.2f} KB/s"))
            update_gui_from_thread("File received successfully")
        except Exception as e:
            root.after(0, messagebox.showerror, "Error", f"An unexpected error occurred: {e}")
        finally:
            s.close()
            update_gui_from_thread("Connection closed")




    #icon
    image_icon1=PhotoImage(file="Images/recevive.png")
    main.iconphoto(False,image_icon1)

    Hbackground=PhotoImage(file="Images/for receiver background.png")
    Label(main,image=Hbackground).place(x=-2,y=0)

    logo=PhotoImage(file='Images/profile.png')
    Label(main,image=logo,bg="#f4fdfd").place(x=10,y=250)

    Label(main,text="Receive",font=('arial',20),bg="#f4fdfe").place(x=100,y=280)

    Label(main,text="Input sender id",font=('arial',10,'bold'),bg="#f4fdfe").place(x=20,y=340)
    SenderID = Entry(main,width=25,fg="black",border=2,bg='white',font=('arial',15))
    SenderID.place(x=20,y=370)
    SenderID.focus()


    Label(main,text="Filename for the incoming file:",font=('arial',10,'bold'),bg="#f4fdfe").place(x=20,y=420)
    incoming_file = Entry(main,width=25,fg="black",border=2,bg='white',font=('arial',15))
    incoming_file.place(x=20,y=450)

    imageicon=PhotoImage(file="Images/arrrow.png")
    rr=Button(main,text="Receive",compound=LEFT,image=imageicon,width=130,bg="#39c790",font="arial 14 bold",command=receiver)
    rr.place(x=20,y=500)

    main.mainloop()

#icon
image_icon=PhotoImage(file="Images/Logo.png")
root.iconphoto(False,image_icon)

Label(root,text="PyLink File Transfer", font=('Acumin Variable Concet',20,'bold'),bg="#f4fdfe").place(x=20,y=30)

Frame(root,width=400, height=2, bg="#f3f5f6").place(x=25,y=80)

send_image=PhotoImage(file="Images/Send.png")
send=Button(root,image=send_image, bg="#f4fdfe",bd=0, command=Send)
send.place(x=50,y=100)

receive_image=PhotoImage(file="Images/recevive.png")
receive=Button(root,image=receive_image, bg="#f4fdfe",bd=0, command=Receive)
receive.place(x=300,y=100)

#label
Label(root,text="Send",font=('Acumin Variable Concept',17,'bold'),bg="#f4fdfe").place(x=65,y=200)
Label(root,text="Receive",font=('Acumin Variable Concept',17,'bold'),bg="#f4fdfe").place(x=300,y=200)


background=PhotoImage(file="Images/background.png")
Label(root,image=background).place(x=-2,y=323)

# Add a login button to your Tkinter window
login_button = Button(
    root,
    text="Login with Google",
    command=on_login_button_clicked,
    bg="#4285F4",  # Background color
    fg="white",    # Text color
    font=("Arial", 14, "bold"),  # Font settings
    padx=10,        # Horizontal padding
    pady=5,         # Vertical padding
    borderwidth=0,  # No border
)
login_button.place(x=20, y=500)


# Create buttons for login and registration with new placement on top of the background image
login_button = ttk.Button(root, text="Login", command=login, style='TButton')
login_button.place(x=120, y=280)  # Adjusted coordinates

register_button = ttk.Button(root, text="Register", command=register, style='TButton')
register_button.place(x=250, y=280)  # Adjusted coordinates


logout_button = ttk.Button(root, text="Logout", command=logout)
logout_button.place(x=180, y=220)  # Adjust the placement as needed


logged_in_user_label = Label(root, text="User:", bg="#f4fdfe", font=('Arial', 12))
logged_in_user_label.place(x=50,y=80)



# CPU Usage Progress Bar and Label
cpu_label = Label(root, text="CPU Usage: ", bg="#f4fdfe", font=('Arial', 8))
cpu_label.place(x=160,y=100)
cpu_progress = ttk.Progressbar(root, length=120, maximum=100)
cpu_progress.place(x=160,y=120)

# RAM Usage Progress Bar and Label
ram_label = Label(root, text="RAM Usage: ", bg="#f4fdfe", font=('Arial', 8))
ram_label.place(x=160,y=140)
ram_progress = ttk.Progressbar(root, length=120, maximum=100)
ram_progress.place(x=160,y=160)

# Call the function to update the resource usage for the first time
root.after(1000, get_resource_usage)


root.mainloop()
