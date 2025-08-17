import tkinter as tk
from tkinter import messagebox
from PIL import Image
from cryptography.fernet import Fernet
import base64
import subprocess
#Alpha Development / Mr.101
def run_zenity_file_select():
    try:
   
        path = subprocess.check_output(['zenity', '--file-selection'], text=True).strip()
        return path
    except subprocess.CalledProcessError:
        return None

def run_zenity_save_file():
    try:

        path = subprocess.check_output(['zenity', '--file-selection', '--save', '--confirm-overwrite'], text=True).strip()
        return path
    except subprocess.CalledProcessError:
        return None

def select_input_image():
    path = run_zenity_file_select()
    if path:
        input_path_var.set(path)

def select_output_image():
    path = run_zenity_save_file()
    if path:
        output_path_var.set(path)

def select_decode_image():
    path = run_zenity_file_select()
    if path:
        decode_path_var.set(path)

def password_to_key(password):
    return base64.urlsafe_b64encode(password.encode('utf-8').ljust(32, b'\0'))

def encrypt_message(message, password):
    key = password_to_key(password)
    f = Fernet(key)
    return f.encrypt(message.encode('utf-8'))

def decrypt_message(token, password):
    key = password_to_key(password)
    f = Fernet(key)
    try:
        return f.decrypt(token).decode('utf-8')
    except:
        return None

def message_to_bits(message_bytes):
    bits = []
    for byte in message_bytes:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)
    return bits

def bits_to_bytes(bits):
    bytes_list = []
    for b in range(0, len(bits), 8):
        byte = 0
        for i in range(8):
            if b + i < len(bits):
                byte = (byte << 1) | bits[b + i]
        bytes_list.append(byte)
    return bytes(bytes_list)

def hide_message():
    img_path = input_path_var.get()
    out_path = output_path_var.get()
    message = message_entry.get("1.0", tk.END).strip()
    password = password_entry.get()

    if not img_path or not out_path or not message or not password:
        messagebox.showerror("Error", "Please fill in all fields")
        return

    try:
        img = Image.open(img_path).convert("RGB")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while opening the image:\n{e}")
        return

    encrypted = encrypt_message(message, password) + b'<<<END>>>'
    bits = message_to_bits(encrypted)

    n_pixels = img.width * img.height * 3
    if len(bits) > n_pixels:
        messagebox.showerror("Error", "The message is too big for this image")
        return

    pixels = list(img.getdata())
    new_pixels = []
    bit_index = 0

    for pixel in pixels:
        r, g, b = pixel
        new_colors = []
        for color in (r, g, b):
            if bit_index < len(bits):
                new_color = (color & ~1) | bits[bit_index]
                bit_index += 1
            else:
                new_color = color
            new_colors.append(new_color)
        new_pixels.append(tuple(new_colors))

    img.putdata(new_pixels)

    try:
        img.save(out_path)
        messagebox.showinfo("Success", f"The message was hidden and saved in:\n{out_path}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while saving the image:\n{e}")

def reveal_message():
    img_path = decode_path_var.get()
    password = decode_password_entry.get()

    if not img_path or not password:
        messagebox.showerror("Error", "Please enter the image path and password")
        return

    try:
        img = Image.open(img_path).convert("RGB")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while opening the image:\n{e}")
        return

    pixels = list(img.getdata())
    bits = []

    for pixel in pixels:
        for color in pixel:
            bits.append(color & 1)

    all_bytes = bits_to_bytes(bits)
    end_marker = b'<<<END>>>'
    end_index = all_bytes.find(end_marker)
    if end_index == -1:
        messagebox.showerror("Error", "The secret message was not found or is corrupt.")
        return

    encrypted_message = all_bytes[:end_index]

    decrypted = decrypt_message(encrypted_message, password)
    if decrypted is None:
        messagebox.showerror("Error", "The password is incorrect or the message is corrupted")
    else:
        messagebox.showinfo("Extracted message", decrypted)



root = tk.Tk()
root.title("Alpha _Steganography")
root.geometry("1920x1080")
root.configure(bg="#2e3f4f")

font_header = ("Arial", 14, "bold")
font_label = ("Arial", 11)
button_color_hide = "#4caf50"
button_color_reveal = "#2196f3"
button_fg = "white"

input_path_var = tk.StringVar()
output_path_var = tk.StringVar()
decode_path_var = tk.StringVar()

tk.Label(root, text="Hide message in image", font=font_header, bg="#2e3f4f", fg="white").pack(pady=8)

tk.Button(root, text="Select input image", command=select_input_image, bg="#455a64", fg="white", width=20).pack()
tk.Entry(root, textvariable=input_path_var, width=60).pack(pady=5)

tk.Button(root, text="Select output save path", command=select_output_image, bg="#455a64", fg="white", width=20).pack()
tk.Entry(root, textvariable=output_path_var, width=60).pack(pady=5)

tk.Label(root, text="Message (Persian or English):", font=font_label, bg="#2e3f4f", fg="white").pack()
message_entry = tk.Text(root, height=5)
message_entry.pack(pady=5)

tk.Label(root, text="Password :", font=font_label, bg="#2e3f4f", fg="white").pack()
password_entry = tk.Entry(root, show="*")
password_entry.pack(pady=5)

tk.Button(root, text="Hide message", command=hide_message, bg=button_color_hide, fg=button_fg, width=20).pack(pady=10)

tk.Label(root, text="-"*60, bg="#2e3f4f", fg="white").pack(pady=10)

tk.Label(root, text="Extracting the hidden message", font=font_header, bg="#2e3f4f", fg="white").pack(pady=8)

tk.Button(root, text="Select hidden image", command=select_decode_image, bg="#455a64", fg="white", width=20).pack()
tk.Entry(root, textvariable=decode_path_var, width=60).pack(pady=5)

tk.Label(root, text="Password :", font=font_label, bg="#2e3f4f", fg="white").pack()
decode_password_entry = tk.Entry(root, show="*")
decode_password_entry.pack(pady=5)

tk.Button(root, text="Message Extraction", command=reveal_message, bg=button_color_reveal, fg=button_fg, width=20).pack(pady=10)

root.mainloop()
