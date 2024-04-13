import tkinter as tk
from tkinter import filedialog
from PIL import Image
from Crypto.Cipher import AES
import base64

# Globalna zmienna dla klucza szyfrowania
v_key: bytes = b'This is a key123'

"""
Dopasowanie łańcucha wejściowego `s`, aby jego długość była wielokrotnością rozmiaru bloku AES.
Argumenty:
    s (str): Łańcuch wejściowy do dopasowania.
Zwraca:
str: Dopasowany łańcuch.
"""
def pad(s: str) -> str:
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

"""
Usuwanie dopełnienia z łańcucha `s`.
Argumenty:
    s (str): Łańcuch z dopełnieniem.
Zwraca:
    str: Łańcuch bez dopełnienia.
"""
def unpad(s: str) -> str:
    return s[:-ord(s[len(s)-1:])]

"""
Szyfrowanie wiadomości przy użyciu szyfrowania AES w trybie ECB.
Argumenty:
    message (str): Wiadomość do zaszyfrowania.
    key (bytes): Klucz szyfrowania.
Zwraca:
    bytes: Zaszyfrowana wiadomość w formacie base64.
"""
def encrypt_message(message: str, key: bytes = v_key) -> bytes:
    message = pad(message)
    cipher = AES.new(key, AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(message.encode()))

"""
Deszyfrowanie wiadomośi zaszyfrowanej w formacie base64 przy użyciu szyfrowania AES w trybie ECB.
Argumenty:
    encrypted (bytes): Zaszyfrowana wiadomość.
    key (bytes): Klucz deszyfrujący.
Zwraca:
    str: Odszyfrowana wiadomość.
"""
def decrypt_message(encrypted: bytes, key: bytes = v_key) -> str:
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(encrypted))
    return unpad(decrypted.decode())

"""
Ukrywanie tekstu w obrazie przez szyfrowanie i manipulację pikselami.
Argumenty:
    img (Image.Image): Obraz, w którym ma być ukryty tekst.
    text (str): Tekst do ukrycia.
    key (bytes): Klucz szyfrowania.
Zwraca:
    Image.Image: Obraz z ukrytym tekstem.
"""
def hide_text(img: Image.Image, text: str, key: bytes = v_key) -> Image.Image:
    encrypted_text = encrypt_message(text, key)
    bytes_text = encrypted_text
    length = len(bytes_text)
    len_bits = f'{length:032b}'

    img_data = list(img.getdata())
    index = 0

    for bit in len_bits:
        pixel = list(img_data[index])
        pixel[0] = (pixel[0] & ~1) | int(bit)
        img_data[index] = tuple(pixel)
        index += 1

    for byte in bytes_text:
        for bit in range(7, -1, -1):
            pixel = list(img_data[index])
            pixel[0] = (pixel[0] & ~1) | ((byte >> bit) & 1)
            img_data[index] = tuple(pixel)
            index += 1

    img.putdata(img_data)
    return img

"""
Otwieranie okna dialogowego do wyboru pliku obrazu, ukrycie w nim tekstu, a następnie zapisanie zmodyfikowanego obrazu.
"""
def embed_text():

    text = entry_text.get()

    if not text:
        tk.messagebox.showerror(title='Error', message='Najpierw wprowadź tekst.')
        return
    else:
        file_path = filedialog.askopenfilename()
        if file_path:
            img = Image.open(file_path)
            img = img.convert("RGB")

            img = hide_text(img, text)
            save_path = filedialog.asksaveasfilename(defaultextension=".png")
            img.save(save_path, "PNG")
            entry_text.delete(0, tk.END)
        else:
            tk.messagebox.showerror(title='Error', message='Nie udało się otworzyć obrazu.')
            entry_text.delete(0, tk.END)


"""
Zapisanie obrazu w formacie PNG używając okna dialogowego do wyboru ścieżki zapisu.
Argumenty:
    image (Image.Image): Obraz do zapisania.
"""
def save_image(image: Image.Image):
    file_path = filedialog.asksaveasfilename(defaultextension=".png")
    if file_path:
        image.save(file_path, "PNG")

"""
Odkrywanie ukrytego tekstu w obrazie.
Argumenty:
    img (Image.Image): Obraz, z którego tekst zostanie odkryty.
    key (bytes): Klucz deszyfrujący.
Zwraca:
    str: Odkryty tekst.
"""
def reveal_text(img: Image.Image, key: bytes = v_key) -> str:
    img_data = list(img.getdata())
    length_bits = ''.join([str(img_data[i][0] & 1) for i in range(32)])
    length = int(length_bits, 2)

    binary_data = ''
    for i in range(32, 32 + length * 8):
        binary_data += str(img_data[i][0] & 1)

    bytes_data = bytes([int(binary_data[i:i+8], 2) for i in range(0, len(binary_data), 8)])
    decrypted_text = decrypt_message(bytes_data, key)
    return decrypted_text

"""
Otwieranie obrazu, odkrywanie i wyświetlanie ukrytego tekstu.
"""
def open_image_and_reveal_text():
    file_path = filedialog.askopenfilename()
    if file_path:
        img = Image.open(file_path)
        img = img.convert("RGB")
        revealed_text = reveal_text(img)
        print(revealed_text)
        tk.messagebox.showinfo("Odkryty tekst", "Odkryty tekst: " + revealed_text)

"""
Zakończenie działania aplikacji
"""
def end_app():
    root.destroy()


"""
GUI
"""
root = tk.Tk()
root.title("Steganografia")

entry_text = tk.Entry(root, width=50)
entry_text.pack()

btn_hide = tk.Button(root, text="Wczytaj obraz i ukryj wprowadzony tekst", command=embed_text)
btn_hide.pack()

btn_reveal = tk.Button(root, text="Otwórz obraz i odkryj tekst", command=open_image_and_reveal_text)
btn_reveal.pack()

panel = tk.Label(root)
panel.pack()

end_button = tk.Button(root, text="Wyjdź", command=end_app)
end_button.pack()

root.mainloop()
