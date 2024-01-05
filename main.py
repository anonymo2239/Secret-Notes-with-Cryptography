import tkinter as tk
from tkinter import messagebox
from PIL import ImageTk, Image
import base64

window = tk.Tk()
window.title("Secret Notes")
window.minsize(width=400, height=700)


def encrypt(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def decrypt(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def create_txt():
    if entryTitle.get() == "" or txtSecret.get("1.0", 'end-1c') == "":
        messagebox.showinfo("Info", "Please enter both title and note.")
    else:
        title = entryTitle.get()
        try:
            with open(f"C:/Users/Alperen Arda/Desktop/PythonBootCamp/mysecret.txt", mode='a') as dosya:
                dosya.write("\n" + title + "\n" + encrypt(entryKey.get(), txtSecret.get("1.0", 'end-1c')))
            messagebox.showinfo("Message", "The note has been saved to mysecret.txt file.")
        except FileNotFoundError:
            with open(f"mysecret.txt", mode='w') as dosya:
                dosya.write("\n" + title + "\n" + encrypt(entryKey.get(), txtSecret.get("1.0", 'end-1c')))
            messagebox.showinfo("Message", "The note has been saved to mysecret.txt file.")
        finally:
            entryTitle.delete(0, tk.END)
            txtSecret.delete("1.0", tk.END)
            entryKey.delete(0, tk.END)


def decode_txt():
    message_encrypted = txtSecret.get("1.0", tk.END)
    master_secret = entryKey.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showerror(title="Error!", message="Please enter both key and code.")
    else:
        try:
            decrypted_message = decrypt(master_secret, message_encrypted)
            txtSecret.delete("1.0", tk.END)
            txtSecret.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please enter encrypted text!")


original_img = Image.open("bizd.gif")
resized_img = original_img.resize((150, 150), Image.Resampling.LANCZOS)

img = ImageTk.PhotoImage(resized_img)
panel = tk.Label(window, image=img)
panel.pack(side="top", fill="none", expand=False)

lblEnterTitle = tk.Label(text="Enter your title", font=("Montserrat", 12, 'normal'))
lblEnterTitle.pack(side="left")
window.update()
lblEnterTitle.place(x=window.winfo_width() / 2 - lblEnterTitle.winfo_width() / 2, y=150)

entryTitle = tk.Entry(width=30)
entryTitle.pack(side="left")
window.update()
entryTitle.place(x=window.winfo_width() / 2 - entryTitle.winfo_width() / 2, y=180)

txtSecret = tk.Text(width=40, height=21)
txtSecret.place(x=0, y=0)
window.update()
txtSecret.place(x=window.winfo_width() / 2 - txtSecret.winfo_width() / 2, y=210)

lblEnterKey = tk.Label(text="Enter master key", font=("Montserrat", 12, 'normal'))
lblEnterKey.pack(side="left")
window.update()
lblEnterKey.place(x=window.winfo_width() / 2 - lblEnterKey.winfo_width() / 2, y=560)

entryKey = tk.Entry(width=30)
entryKey.pack(side="left")
window.update()
entryKey.place(x=window.winfo_width() / 2 - entryKey.winfo_width() / 2, y=590)

btnSave = tk.Button(text='Save & Encrypt', font=("Montserrat", 9), command=create_txt)
btnSave.pack(side="left")
window.update()
btnSave.place(x=window.winfo_width() / 2 - btnSave.winfo_width() / 2, y=615)

btnDecry = tk.Button(text='Decrypt', font=("Montserrat", 9), command=decode_txt)
btnDecry.pack(side="left")
window.update()
btnDecry.place(x=window.winfo_width() / 2 - btnDecry.winfo_width() / 2, y=645)

window.mainloop()
