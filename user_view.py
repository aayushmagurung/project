import tkinter as tk
from tkinter import messagebox
from auth import authenticate, get_user_details, add_user, delete_user, get_student_grades, get_student_eca, update_student_profile


def change_password(user):
    """
    Allow the user to change their password with password visibility toggle.
    """
    def toggle_password(entry, toggle_button):
        """
        Toggle the visibility of the password in the entry widget.
        """
        if entry.cget("show") == "*":
            entry.config(show="")
            toggle_button.config(text="Hide")
        else:
            entry.config(show="*")
            toggle_button.config(text="Show")

    def submit_change():
        current_password = current_password_entry.get()
        new_password = new_password_entry.get()

        # Verify current password
        try:
            with open("data/passwords.txt", "r") as file:
                lines = file.readlines()

            updated = False
            with open("data/passwords.txt", "w") as file:
                for line in lines:
                    stored_username, stored_password, role = line.strip().split(",")
                    if user.username == stored_username:
                        if current_password == stored_password:
                            file.write(f"{stored_username},{new_password},{role}\n")
                            updated = True
                        else:
                            messagebox.showerror("Error", "Current password is incorrect.")
                            file.write(line)
                            return
                    else:
                        file.write(line)

            if updated:
                messagebox.showinfo("Success", "Password changed successfully!")
                change_password_window.destroy()
            else:
                messagebox.showerror("Error", "Failed to change password.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    # Create a new window for changing the password
    change_password_window = tk.Toplevel()
    change_password_window.title("Change Password")
    change_password_window.geometry("400x250")

    # Current password
    tk.Label(change_password_window, text="Current Password:").pack(pady=5)
    current_password_frame = tk.Frame(change_password_window)
    current_password_frame.pack(pady=5)
    current_password_entry = tk.Entry(current_password_frame, show="*")
    current_password_entry.pack(side=tk.LEFT, padx=5)
    current_password_toggle = tk.Button(current_password_frame, text="Show", command=lambda: toggle_password(current_password_entry, current_password_toggle))
    current_password_toggle.pack(side=tk.LEFT)

    # New password
    tk.Label(change_password_window, text="New Password:").pack(pady=5)
    new_password_frame = tk.Frame(change_password_window)
    new_password_frame.pack(pady=5)
    new_password_entry = tk.Entry(new_password_frame, show="*")
    new_password_entry.pack(side=tk.LEFT, padx=5)
    new_password_toggle = tk.Button(new_password_frame, text="Show", command=lambda: toggle_password(new_password_entry, new_password_toggle))
    new_password_toggle.pack(side=tk.LEFT)

    # Submit button
    tk.Button(change_password_window, text="Submit", command=submit_change).pack(pady=10)


def admin_dashboard(user):
    """
    Admin dashboard functionality.
    """
    def logout():
        admin_window.destroy()

    admin_window = tk.Toplevel()
    admin_window.title("Admin Dashboard")
    admin_window.geometry("400x300")

    tk.Label(admin_window, text=f"Welcome, {user.full_name}!", font=("Arial", 16)).pack(pady=10)

    tk.Button(admin_window, text="Add User", command=lambda: add_user_ui()).pack(pady=10)
    tk.Button(admin_window, text="Delete User", command=lambda: delete_user_ui()).pack(pady=10)
    tk.Button(admin_window, text="Change Password", command=lambda: change_password(user)).pack(pady=10)
    tk.Button(admin_window, text="Logout", command=logout).pack(pady=10)


def student_dashboard(user):
    """
    Student dashboard functionality.
    """
    def logout():
        student_window.destroy()

    student_window = tk.Toplevel()
    student_window.title("Student Dashboard")
    student_window.geometry("400x300")

    tk.Label(student_window, text=f"Welcome, {user.full_name}!", font=("Arial", 16)).pack(pady=10)

    tk.Button(student_window, text="View Details", command=lambda: view_details(user)).pack(pady=10)
    tk.Button(student_window, text="Update Profile", command=lambda: update_profile(user)).pack(pady=10)
    tk.Button(student_window, text="Change Password", command=lambda: change_password(user)).pack(pady=10)
    tk.Button(student_window, text="Logout", command=logout).pack(pady=10)


def forgot_password():
    """
    Functionality for resetting a forgotten password.
    """
    def submit_reset():
        username = username_entry.get()
        new_password = new_password_entry.get()

        # Check if the username exists in passwords.txt
        try:
            with open("data/passwords.txt", "r") as file:
                lines = file.readlines()

            updated = False
            with open("data/passwords.txt", "w") as file:
                for line in lines:
                    stored_username, stored_password, role = line.strip().split(",")
                    if username == stored_username:
                        file.write(f"{username},{new_password},{role}\n")
                        updated = True
                    else:
                        file.write(line)

            if updated:
                messagebox.showinfo("Success", "Password reset successfully!")
                reset_window.destroy()
            else:
                messagebox.showerror("Error", "Username not found.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    # Create a new window for password reset
    reset_window = tk.Toplevel()
    reset_window.title("Forgot Password")
    reset_window.geometry("300x200")

    tk.Label(reset_window, text="Enter your username:").pack(pady=5)
    username_entry = tk.Entry(reset_window)
    username_entry.pack(pady=5)

    tk.Label(reset_window, text="Enter new password:").pack(pady=5)
    new_password_entry = tk.Entry(reset_window, show="*")
    new_password_entry.pack(pady=5)

    tk.Button(reset_window, text="Submit", command=submit_reset).pack(pady=10)


def login():
    username = username_entry.get()
    password = password_entry.get()

    # Authenticate the user
    role = authenticate(username, password)
    if role:
        user = get_user_details(username)
        if user:
            messagebox.showinfo("Login Successful",
                                f"Welcome, {user.full_name} ({user.role})!")
            if role == "admin":
                admin_dashboard(user)
            elif role == "student":
                student_dashboard(user)
    else:
        messagebox.showerror("Login Failed", "Invalid username or password")


def main():
    root = tk.Tk()
    root.title("Login System")
    root.geometry("900x700")

    # Create a frame to center the elements
    frame = tk.Frame(root)
    frame.pack(expand=True)

    # Username label and entry
    tk.Label(frame, text="Username:").pack(pady=5)
    global username_entry
    username_entry = tk.Entry(frame)
    username_entry.pack(pady=5)

    # Password label and entry
    tk.Label(frame, text="Password:").pack(pady=5)
    global password_entry
    password_entry = tk.Entry(frame, show="*")
    password_entry.pack(pady=5)

    # Login button
    tk.Button(frame, text="Login", command=login).pack(pady=10)

    # Forgot Password button
    tk.Button(frame, text="Forgot Password?", command=forgot_password).pack(pady=5)

    root.mainloop()


if __name__ == "__main__":
    main()