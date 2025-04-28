from PIL import Image, PngImagePlugin
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def encrypt_image(input_path, output_path, key, password):
    with Image.open(input_path) as im:
        im = im.convert("RGB")
        pixels = im.load()
        width, height = im.size

        for x in range(width):
            for y in range(height):
                r, g, b = pixels[x, y]
                pixels[x, y] = ((r + key) % 256, (g + key) % 256, (b + key) % 256)

        meta = PngImagePlugin.PngInfo()
        password_hash = hash_password(password)
        meta.add_text("PasswordHash", password_hash)

        im.save(output_path, pnginfo=meta)

def decrypt_image(input_path, output_path, key, password):
    with Image.open(input_path) as im:
        im = im.convert("RGB")
        pixels = im.load()
        width, height = im.size

        info = im.info
        stored_password_hash = info.get("PasswordHash")

        if stored_password_hash is None:
            raise ValueError("No password protection found on this image.")

        if hash_password(password) != stored_password_hash:
            raise ValueError("Incorrect password. Decryption failed.")

        for x in range(width):
            for y in range(height):
                r, g, b = pixels[x, y]
                pixels[x, y] = ((r - key) % 256, (g - key) % 256, (b - key) % 256)

        im.save(output_path)

class ImageEncryptorApp:
    def __init__(self, master):
        self.master = master
        master.title("Image Encryptor/Decryptor")
        master.geometry("450x400")
        master.configure(bg="#f0f0f0")

        self.mode = tk.StringVar(value="encrypt")

        title_label = tk.Label(master, text="Image Encryptor/Decryptor", font=("Arial", 18, "bold"), bg="#f0f0f0")
        title_label.pack(pady=10)

        mode_frame = tk.Frame(master, bg="#f0f0f0")
        mode_frame.pack(pady=5)

        self.radio_encrypt = tk.Radiobutton(mode_frame, text="Encrypt", variable=self.mode, value="encrypt", bg="#f0f0f0", font=("Arial", 12))
        self.radio_encrypt.pack(side="left", padx=20)

        self.radio_decrypt = tk.Radiobutton(mode_frame, text="Decrypt", variable=self.mode, value="decrypt", bg="#f0f0f0", font=("Arial", 12))
        self.radio_decrypt.pack(side="left", padx=20)

        self.button_select_input = tk.Button(master, text="Select Input Image", command=self.select_input_image, font=("Arial", 12))
        self.button_select_input.pack(pady=10)

        self.button_select_output = tk.Button(master, text="Select Output Location", command=self.select_output_image, font=("Arial", 12))
        self.button_select_output.pack(pady=10)

        key_frame = tk.Frame(master, bg="#f0f0f0")
        key_frame.pack(pady=10)

        self.label_key = tk.Label(key_frame, text="Enter Key (integer):", font=("Arial", 12), bg="#f0f0f0")
        self.label_key.pack(side="left", padx=5)

        self.entry_key = tk.Entry(key_frame, font=("Arial", 12), width=10)
        self.entry_key.pack(side="left", padx=5)

        password_frame = tk.Frame(master, bg="#f0f0f0")
        password_frame.pack(pady=10)

        self.label_password = tk.Label(password_frame, text="Enter Password:", font=("Arial", 12), bg="#f0f0f0")
        self.label_password.pack(side="left", padx=5)

        self.entry_password = tk.Entry(password_frame, font=("Arial", 12), width=15, show="*")
        self.entry_password.pack(side="left", padx=5)

        self.button_start = tk.Button(master, text="Start Process", command=self.start_process, font=("Arial", 14), bg="#4CAF50", fg="white")
        self.button_start.pack(pady=20)

        # File paths
        self.input_path = ""
        self.output_path = ""

    def select_input_image(self):
        self.input_path = filedialog.askopenfilename(title="Select input image", filetypes=[("PNG files", "*.png")])

    def select_output_image(self):
        self.output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])

    def start_process(self):
        if not self.input_path or not self.output_path:
            messagebox.showerror("Error", "Please select both input and output image files.")
            return

        try:
            key = int(self.entry_key.get())
            password = self.entry_password.get()

            if self.mode.get() == "encrypt":
                encrypt_image(self.input_path, self.output_path, key, password)
                messagebox.showinfo("Success", "Image encrypted successfully!")
            else:
                decrypt_image(self.input_path, self.output_path, key, password)
                messagebox.showinfo("Success", "Image decrypted successfully!")
        except ValueError as e:
            messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Something went wrong: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ImageEncryptorApp(root)
    root.mainloop()
