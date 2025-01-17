import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
import tkinter.simpledialog
import tempfile, base64, zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import secrets
import hashlib
import string
import os
import json

# Console output at startup
print("PassContainer v. 1.0\n2025 © Data Animal")

# Global variables
password_container = {"Default": "Default"}
user = "Default user"
temp = ""
showingPasses1 = True
showingPasses2 = True
showingPasses3 = True
showingPasses4 = True
showingPasses5 = True
showingPasses6 = True
showingPasses7 = True
showingPasses8 = True

# Transparent icon settings
ICON = zlib.decompress(base64.b64decode('eJxjYGAEQgEBBiDJwZDBy'
                                        'sAgxsDAoAHEQCEGBQaIOAg4sDIgACMUj4JRMApGwQgF/ykEAFXxQRc='))
_, ICON_PATH = tempfile.mkstemp()
with open(ICON_PATH, 'wb') as icon_file:
    icon_file.write(ICON)

# Create a personal cipher for encrypting (can't touch this!)
def personalCipher(name, passwd, fakefile):
    # No extra code provided
    if not fakefile and len(personalCode.get()) < 3:
        for i in range(2, len(name)):
            if len(name) % i != 0:
                name = name[::-1]
        if len(passwd) % 2 == 0:
            passwd = passwd[::-1]
        move = 6
        new_name = ""
        for e in name:
            new_ascii = ord(e) + move
            new_char = chr(new_ascii)
            new_name += new_char
            move = 3 if move == 6 else 6
        name = new_name
        newString = ""
        index1 = 0
        index2 = 0
        while index1 < len(name) or index2 < len(passwd):
            if index1 < len(name):
                newString += name[index1]
                index1 += 1
            if index2 < len(passwd):
                newString += passwd[index2]
                index2 += 1
        if len(newString) > 16:
            while len(newString) > 16:
                newString = newString[:-1]
        elif len(newString) < 16:
            i = 0
            while len(newString) < 16:
                newString += newString[i]
                i += 1
        newString = newString[:0] + newString[0:7][::-1] + newString[7:]
        mixed_string = ""
        nextmove = 1
        for y, c in enumerate(newString):
            if y % 2 == 1:
                new_char = chr(ord(c) + nextmove)
                mixed_string += new_char
                nextmove += 1
            else:
                mixed_string += c
        return mixed_string

    # Extra code provided
    elif not fakefile and len(personalCode.get()) >= 3:
        pcode = personalCode.get()
        num1 = ord(pcode[0])
        num2 = ord(pcode[1])
        num3 = ord(pcode[2])
        big = max(num1, num2, num3)
        small = min(num1, num2, num3)
        outcome = big - small - 32
        mixed_name = ""
        for r, ch in enumerate(name):
            if r % 2 == 0:
                mixed_name += ch
            else:
                new_ascii = ord(ch) + outcome
                mixed_name += chr(new_ascii)
        # The outcome of magic number will be something between 1 and 65
        magicNumber = round((((num3*num2)/3)*num1)/10000,0)
        # The outcome of space number will be something between 32 and 320 (roughly)
        spaceNumber = (num1+num2+num2)-(2*min(num1,num2,num3))
        mixed = ""
        i = 0
        j = 0
        # Option 1
        if magicNumber >= 33:
            finalNumber = str(round((spaceNumber+magicNumber)-(min(spaceNumber,magicNumber)/2),0))
            passwd = passwd[::-1]
            new_name = ""
            for e in name:
                new_ascii = ord(e) + 2
                new_char = chr(new_ascii)
                new_name += new_char
            name = new_name
            positionchar = str(spaceNumber)[-1]
            while i < len(passwd) or j < len(name):
                mixed += passwd[i:i + 3]
                i += 3
                if j < len(name):
                    mixed += name[j]
                    j += 1
            mixed = mixed[:1] + pcode[1] + mixed[1:]
        # Option 2
        elif magicNumber < 33 and magicNumber >= 15:
            finalNumber = str(round(num3*(spaceNumber/10),0))
            name = name[::-1]
            new_name = ""
            for e in name:
                new_ascii = ord(e) + 5
                new_char = chr(new_ascii)
                new_name += new_char
            name = new_name
            positionchar = str(spaceNumber)[-2]
            while i < len(passwd) or j < len(name):
                mixed += passwd[i:i + 2]
                i += 2
                if j < len(name):
                    mixed += name[j]
                    j += 1
            mixed = mixed[:0] + pcode[1] + mixed[0:]
        # Option 3
        elif magicNumber < 15:
            finalNumber = str(round(spaceNumber*(magicNumber*2),0))
            name = name[::-1]
            passwd = passwd[::-1]
            new_name = ""
            for e in name:
                new_ascii = ord(e) + 6
                new_char = chr(new_ascii)
                new_name += new_char
            name = new_name
            positionchar = str(magicNumber)[-3]
            third_option = True
            while i < len(passwd) or j < len(name):
                if third_option:
                    mixed += passwd[i:i + 3]
                    i += 3
                    third_option = False
                else:
                    mixed += passwd[i:i + 2]
                    i += 2
                    third_option = True
                if j < len(name):
                    mixed += name[j]
                    j += 1
            mixed = mixed[:2] + pcode[0] + mixed[2:]
        # This affects all options 1-3
        t = finalNumber[0] + finalNumber[1]
        t = int(t)
        t += magicNumber
        while t < 32:
            t += 3
        asciichar = chr(int(t))
        numberchar = finalNumber[-3]
        templist = list(mixed)
        templist.insert(int(positionchar), asciichar)
        templist.insert((int(positionchar)+2), numberchar)
        newString = ''.join(templist)
        if len(newString) > 16:
            while len(newString) > 16:
                newString = newString[:-1]
        elif len(newString) < 16:
            i = 0
            while len(newString) < 16:
                newString += newString[i]
                i += 1
        if spaceNumber < 120:
            newString = newString[:0] + newString[0:7][::-1] + newString[7:]
        return newString

    # Make fake cipher
    else:
        fake_cipher = list(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for i in range(16))
        newString = ''.join(fake_cipher)
        return newString

def fake_savefile():
    var = personalCipher("user", "temp", True)
    key = var.encode()
    cipher = AES.new(key, AES.MODE_CBC)
    data = []
    for i in range(24):
        inputLength = secrets.choice(range(5, 21))
        generatedInput = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for i in range(inputLength))
        data.append(generatedInput)
    notesLength = secrets.choice(range(0, 20))
    generatedNotes = ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(notesLength))
    data.append(generatedNotes)
    savefile = "\n".join(data)
    savefile = savefile.encode()
    cryptedfile = cipher.encrypt(pad(savefile,AES.block_size))
    file = filedialog.asksaveasfile(mode='wb')
    if file != None:
        file.write(cipher.iv)
        file.write(cryptedfile)
        file.close()

# Save encrypted file using the personalized cipher
def save_file():
    notes.edit_modified(False)
    global user
    global temp
    var = personalCipher(user, temp, False)
    key = var.encode()
    cipher = AES.new(key, AES.MODE_CBC)
    data = []
    site_vars = [
        currentSite1, currentSite2, currentSite3,
        currentSite4, currentSite5, currentSite6,
        currentSite7, currentSite8
    ]
    user_vars = [
        currentUser1, currentUser2, currentUser3,
        currentUser4, currentUser5, currentUser6,
        currentUser7, currentUser8
    ]
    pass_vars = [
        currentPass1, currentPass2, currentPass3,
        currentPass4, currentPass5, currentPass6,
        currentPass7, currentPass8
    ]
    for site, user, password in zip(site_vars, user_vars, pass_vars):
        data.append(site.get())
        data.append(user.get())
        data.append(password.get())
    data.append(notes.get(1.0, 'end'))
    savefile = "\n".join(data)
    savefile = savefile.encode()
    cryptedfile = cipher.encrypt(pad(savefile,AES.block_size))
    file = filedialog.asksaveasfile(mode='wb')
    if file != None:
        file.write(cipher.iv)
        file.write(cryptedfile)
        file.close()

# Load an encrypted file using the personalized cipher
def load_file():
    try:
        global user
        global temp
        var = personalCipher(user, temp, False)
        key = var.encode()
        clear_data()
        filepath = filedialog.askopenfilename()
        if filepath:
            with open(filepath, 'rb') as f:
                iv = f.read(len(var))
                ciphertext = f.read()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decryptedfile = unpad(cipher.decrypt(ciphertext),AES.block_size)
        decryptedfile = decryptedfile.decode()
        data = decryptedfile.splitlines()
        currentSite1.insert(0, data[0])
        currentUser1.insert(0, data[1])
        currentPass1.insert(0, data[2])
        currentSite2.insert(0, data[3])
        currentUser2.insert(0, data[4])
        currentPass2.insert(0, data[5])
        currentSite3.insert(0, data[6])
        currentUser3.insert(0, data[7])
        currentPass3.insert(0, data[8])
        currentSite4.insert(0, data[9])
        currentUser4.insert(0, data[10])
        currentPass4.insert(0, data[11])
        currentSite5.insert(0, data[12])
        currentUser5.insert(0, data[13])
        currentPass5.insert(0, data[14])
        currentSite6.insert(0, data[15])
        currentUser6.insert(0, data[16])
        currentPass6.insert(0, data[17])
        currentSite7.insert(0, data[18])
        currentUser7.insert(0, data[19])
        currentPass7.insert(0, data[20])
        currentSite8.insert(0, data[21])
        currentUser8.insert(0, data[22])
        currentPass8.insert(0, data[23])
        notes.insert('end', data[24])
        notes.edit_modified(False)
    except:
        messagebox.showinfo(title="Denied entry", message="No access")

# Load userlist
def load_userlist():
    if not os.path.exists("datapack.json"):
        save_userlist()
    with open("datapack.json", "r") as f:
        loaded_data = json.load(f)
        password_container.update(loaded_data)

# Save userlist
def save_userlist():
    json_string = json.dumps(password_container)
    with open("datapack.json", "w") as f:
        f.write(json_string)

# Copy username to clipboard
def copy_user(number):
    username_entries = [
        currentUser1, currentUser2, currentUser3, currentUser4,
        currentUser5, currentUser6, currentUser7, currentUser8
    ]
    copiedText = username_entries[number - 1].get()
    root.clipboard_clear()
    root.clipboard_append(copiedText)

# Copy password to clipboard
def copy_password(number):
    password_entries = [
        currentPass1, currentPass2, currentPass3, currentPass4,
        currentPass5, currentPass6, currentPass7, currentPass8
    ]
    copiedText = password_entries[number - 1].get()
    root.clipboard_clear()
    root.clipboard_append(copiedText)

# Log in function
def login():
    try:
        usernm = tkinter.simpledialog.askstring("", "Enter username:")
        passwd = tkinter.simpledialog.askstring("", "Enter password:", show='*')
        hashed_username = hashlib.sha512(usernm.encode()).hexdigest()
        hashed_password = hashlib.sha512(passwd.encode()).hexdigest()
        if hashed_username in password_container.keys() and password_container[hashed_username] == hashed_password:
            global user
            global temp
            user = usernm
            temp = passwd
            userLabel.config(text=usernm)
            enableMenuandWidgets()
        else:
            messagebox.showinfo(title="Denied entry", message="Unknown username/password combination")
    except:
        pass

# Log out function
def logout():
    if messagebox.askyesno(title="Log out?", message="Really log out?"):
        global user
        global temp
        user = ""
        temp = ""
        userLabel.config(text="Default user")
        clear_data()
        disableMenuandWidgets()
        personalCode.delete(0, 'end')
        notes.edit_modified(False)

# Clear all data from entries and notebook
def clear_data():
    notes.delete(1.0, 'end')
    for i in range(1, 9):
        globals()[f"currentSite{i}"].delete(0, 'end')
        globals()[f"currentPass{i}"].delete(0, 'end')
        globals()[f"currentUser{i}"].delete(0, 'end')
        globals()[f"showingPasses{i}"] = True
        globals()[f"currentPass{i}"].config(show='*')
        globals()[f"showBtn{i}"].config(text="Show")

# Change username (WARNING: your previously encryoted files won't open anymore!)
def changeName():
    try:
        global user
        passwd = tkinter.simpledialog.askstring("", "Enter password:", show='*')
        hashed_username = hashlib.sha512(user.encode()).hexdigest()
        hashed_password = hashlib.sha512(passwd.encode()).hexdigest()
        if hashed_username in password_container.keys() and password_container[hashed_username] == hashed_password:
            usernm = ""
            while len(usernm) < 2 or len(usernm) > 10 or hashed_username in password_container:
                usernm = tkinter.simpledialog.askstring("", "Enter username:")
                hashed_username = hashlib.sha512(usernm.encode()).hexdigest()
                if len(usernm) < 2 or len(usernm) > 10:
                    messagebox.showinfo(title="Invalid username", message="Username must be between 2 and 10 characters")
                elif hashed_username in password_container:
                    messagebox.showinfo(title="Invalid username", message="This username is already taken")
            hashed_username = hashlib.sha512(user.encode()).hexdigest()
            del password_container[hashed_username]
            hashed_username = hashlib.sha512(usernm.encode()).hexdigest()
            hashed_password = hashlib.sha512(passwd.encode()).hexdigest()
            password_container[hashed_username] = hashed_password
            save_userlist()
            user = usernm
            userLabel.config(text=usernm)
            messagebox.showinfo(title="Username changed", message="Username was changed")
        else:
            messagebox.showinfo(title="Invalid password", message="Invalid password")
    except:
        pass

# Change password (WARNING: your previously encryoted files won't open anymore!)
def changePass():
    try:
        global user
        global temp
        passwd = tkinter.simpledialog.askstring("", "Enter the current password:", show='*')
        hashed_username = hashlib.sha512(user.encode()).hexdigest()
        hashed_password = hashlib.sha512(passwd.encode()).hexdigest()
        if hashed_username in password_container.keys() and password_container[hashed_username] == hashed_password:
            passwd = ""
            while len(passwd) < 8 or len(passwd) > 28:
                passwd = tkinter.simpledialog.askstring("", "Enter new password:", show='*')
                if len(passwd) < 8 or len(passwd) > 28:
                    messagebox.showinfo(title="Invalid password", message="Password must be between 8 and 28 characters")
            passwd_retry = tkinter.simpledialog.askstring("", "Enter the password again:", show='*')
            if passwd == passwd_retry:
                hashed_username = hashlib.sha512(user.encode()).hexdigest()
                del password_container[hashed_username]
                hashed_username = hashlib.sha512(user.encode()).hexdigest()
                hashed_password = hashlib.sha512(passwd.encode()).hexdigest()
                password_container[hashed_username] = hashed_password
                temp = passwd
                save_userlist()
                messagebox.showinfo(title="Password changed", message="Password was changed")
        else:
            messagebox.showinfo(title="Invalid password", message="Invalid password")
    except:
        pass

# Add new user
def addUser():
    try:
        usernm = ""
        while len(usernm) < 2 or len(usernm) > 10 or hashed_username in password_container:
            usernm = tkinter.simpledialog.askstring("", "Enter username:")
            hashed_username = hashlib.sha512(usernm.encode()).hexdigest()
            if len(usernm) < 2 or len(usernm) > 10:
                messagebox.showinfo(title="Invalid username", message="Username must be between 2 and 10 characters")
            elif hashed_username in password_container:
                messagebox.showinfo(title="Invalid username", message="This username is already taken")
        passwd = ""
        while len(passwd) < 8 or len(passwd) > 28:
            passwd = tkinter.simpledialog.askstring("", "Enter password:", show='*')
            if len(passwd) < 8 or len(passwd) > 28:
                messagebox.showinfo(title="Invalid password", message="Password must be between 8 and 28 characters")
        passwd_retry = tkinter.simpledialog.askstring("", "Enter the password again:", show='*')
        if passwd == passwd_retry:
            global user
            global temp
            enableMenuandWidgets()
            print("New user created")
            hashed_username = hashlib.sha512(usernm.encode()).hexdigest()
            hashed_password = hashlib.sha512(passwd.encode()).hexdigest()
            password_container[hashed_username] = hashed_password
            user = usernm
            temp = passwd
            userLabel.config(text=usernm)
            save_userlist()
        else:
            messagebox.showinfo(title="Mismatched password", message="Passwords don't match")
    except:
        pass

# Enable menu and widgets
def enableMenuandWidgets():
    filemenu.entryconfig("Save", state="normal")
    filemenu.entryconfig("Open", state="normal")
    accountmenu.entryconfig("Log in", state="disabled")
    accountmenu.entryconfig("Add user", state="disabled")
    for entry in ("Log out", "Change username", "Change password", "Delete user"):
        accountmenu.entryconfig(entry, state="normal")
    notebook.tab(0, state="normal")
    notebook.tab(1, state="normal")
    currentUser1.place(x=170, y=70)
    currentUser2.place(x=170, y=100)
    currentUser3.place(x=170, y=130)
    currentUser4.place(x=170, y=160)
    currentUser5.place(x=170, y=190)
    currentUser6.place(x=170, y=220)
    currentUser7.place(x=170, y=250)
    currentUser8.place(x=170, y=280)
    currentPass1.place(x=385, y=70)
    currentPass2.place(x=385, y=100)
    currentPass3.place(x=385, y=130)
    currentPass4.place(x=385, y=160)
    currentPass5.place(x=385, y=190)
    currentPass6.place(x=385, y=220)
    currentPass7.place(x=385, y=250)
    currentPass8.place(x=385, y=280)
    copyBtn1.place(x=330, y=65)
    showBtn1.place(x=600, y=65)
    copyBtn2.place(x=330, y=95)
    showBtn2.place(x=600, y=95)
    copyBtn3.place(x=330, y=125)
    showBtn3.place(x=600, y=125)
    copyBtn4.place(x=330, y=155)
    showBtn4.place(x=600, y=155)
    copyBtn5.place(x=330, y=185)
    showBtn5.place(x=600, y=185)
    copyBtn6.place(x=330, y=215)
    showBtn6.place(x=600, y=215)
    copyBtn7.place(x=330, y=245)
    showBtn7.place(x=600, y=245)
    copyBtn8.place(x=330, y=275)
    showBtn8.place(x=600, y=275)
    copyBtn9.place(x=545, y=65)
    copyBtn10.place(x=545, y=95)
    copyBtn11.place(x=545, y=125)
    copyBtn12.place(x=545, y=155)
    copyBtn13.place(x=545, y=185)
    copyBtn14.place(x=545, y=215)
    copyBtn15.place(x=545, y=245)
    copyBtn16.place(x=545, y=275)
    personalCode.place(x=600, y=30)
    notebook.select(0)

# Disable menu and widgets
def disableMenuandWidgets():
    filemenu.entryconfig("Save", state="disabled")
    filemenu.entryconfig("Open", state="disabled")
    accountmenu.entryconfig("Log in", state="normal")
    accountmenu.entryconfig("Add user", state="normal")
    for entry in ("Log out", "Change username", "Change password", "Delete user"):
        accountmenu.entryconfig(entry, state="disabled")
    notebook.tab(0, state="disabled")
    notebook.tab(1, state="disabled")
    widgets_to_hide = [
        currentPass1, currentPass2, currentPass3, currentPass4, currentPass5,
        currentPass6, currentPass7, currentPass8,
        currentUser1, currentUser2, currentUser3, currentUser4, currentUser5,
        currentUser6, currentUser7, currentUser8,
        copyBtn1, showBtn1, copyBtn2, showBtn2, copyBtn3, showBtn3, copyBtn4,
        showBtn4, copyBtn5, showBtn5, copyBtn6, showBtn6, copyBtn7, showBtn7,
        copyBtn8, showBtn8,
        copyBtn9, copyBtn10, copyBtn11, copyBtn12, copyBtn13, copyBtn14,
        copyBtn15, copyBtn16,
        personalCode
    ]
    for widget in widgets_to_hide:
        widget.place_forget()
    global user
    user = "Default user"
    userLabel.config(text=user)

# Delete user (remember to delete your crypted files also, this won't do that!)
def delUser():
    global user
    if messagebox.askyesno(title="Delete user?", message="Really delete this user?"):
        hashed_username = hashlib.sha512(user.encode()).hexdigest()
        if hashed_username in password_container:
            global temp
            del password_container[hashed_username]
            save_userlist()
            messagebox.showinfo(title="Deletion complete", message=f"User {user} deleted")
            disableMenuandWidgets()
            personalCode.delete(0, 'end')
            clear_data()
            temp = ""
            user = ""

# Alter the show/hide status of buttons (this one's ugly, I know)
def show(number):
    if number == 1:
        global showingPasses1
        if showingPasses1:
            currentPass1.config(show='')
            showBtn1.config(text="Hide")
            showingPasses1 = False
        else:
            currentPass1.config(show='*')
            showBtn1.config(text="Show")
            showingPasses1 = True
    elif number == 2:
        global showingPasses2
        if showingPasses2:
            currentPass2.config(show='')
            showBtn2.config(text="Hide")
            showingPasses2 = False
        else:
            currentPass2.config(show='*')
            showBtn2.config(text="Show")
            showingPasses2 = True
    elif number == 3:
        global showingPasses3
        if showingPasses3:
            currentPass3.config(show='')
            showBtn3.config(text="Hide")
            showingPasses3 = False
        else:
            currentPass3.config(show='*')
            showBtn3.config(text="Show")
            showingPasses3 = True
    elif number == 4:
        global showingPasses4
        if showingPasses4:
            currentPass4.config(show='')
            showBtn4.config(text="Hide")
            showingPasses4 = False
        else:
            currentPass4.config(show='*')
            showBtn4.config(text="Show")
            showingPasses4 = True
    if number == 5:
        global showingPasses5
        if showingPasses5:
            currentPass5.config(show='')
            showBtn5.config(text="Hide")
            showingPasses5 = False
        else:
            currentPass5.config(show='*')
            showBtn5.config(text="Show")
            showingPasses5 = True
    elif number == 6:
        global showingPasses6
        if showingPasses6:
            currentPass6.config(show='')
            showBtn6.config(text="Hide")
            showingPasses6 = False
        else:
            currentPass6.config(show='*')
            showBtn6.config(text="Show")
            showingPasses6 = True
    elif number == 7:
        global showingPasses7
        if showingPasses7:
            currentPass7.config(show='')
            showBtn7.config(text="Hide")
            showingPasses7 = False
        else:
            currentPass7.config(show='*')
            showBtn7.config(text="Show")
            showingPasses7 = True
    elif number == 8:
        global showingPasses8
        if showingPasses8:
            currentPass8.config(show='')
            showBtn8.config(text="Hide")
            showingPasses8 = False
        else:
            currentPass8.config(show='*')
            showBtn8.config(text="Show")
            showingPasses8 = True

# Check if notes is modified (this one's still incomplete - won't check the status of entry fields)
def anything_modified():
    if notes.edit_modified():
        return True
    else:
        return False

# Ensure quitting
def on_closing():
    if anything_modified():
        if messagebox.askyesno(title="Quit?", message="You have unsaved project.\nReally quit without saving?"):
            root.destroy()
    else:
        root.destroy()

# Create random users to hide your real account
def randomHash():
    userAmount = tkinter.simpledialog.askinteger("", "How many random users:")
    try:
        if userAmount > 0 and userAmount < 100:
            for i in range(userAmount):
                userNameLength = secrets.choice(range(5, 15))
                userPasswordLength = secrets.choice(range(8, 29))
                userName = list(secrets.choice(string.ascii_letters + string.digits) for i in range(userNameLength))
                generated_username = ''.join(userName)
                password = list(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for i in range(userPasswordLength))
                generated_password = ''.join(password)
                hashed_username = hashlib.sha512(generated_username.encode()).hexdigest()
                hashed_password = hashlib.sha512(generated_password.encode()).hexdigest()
                password_container[hashed_username] = hashed_password
                # Uncomment the next line if you want to print generated usernames and passwords to console
                #print(f"User {i+1} name: {generated_username} pass: {generated_password}")
            save_userlist()
        else:
            messagebox.showinfo(title="Invalid input", message="Choose number between 1-100.")
    except:
        pass

# Root window setup
root = tk.Tk()
root.title("PassContainer")
root.geometry("680x350")
root.resizable(False, False)
root.config(bg='#ADD8E6')
root.iconbitmap(default=ICON_PATH)
root.protocol("WM_DELETE_WINDOW", on_closing)

# Menubar setup
menubar = tk.Menu(root)
root.config(menu = menubar)
filemenu = tk.Menu(menubar,tearoff=0)
menubar.add_cascade(label="File",menu=filemenu)
filemenu.add_command(label="Open", state="disabled", command=load_file)
filemenu.add_command(label="Save", state="disabled", command=save_file)
filemenu.add_separator()
filemenu.add_command(label="Exit", command=on_closing)
accountmenu = tk.Menu(menubar,tearoff=0)
menubar.add_cascade(label="Account",menu=accountmenu)
accountmenu.add_command(label="Log in", command=login)
accountmenu.add_command(label="Log out", state="disabled", command=logout)
accountmenu.add_command(label="Change username", state="disabled", command=changeName)
accountmenu.add_command(label="Change password", state="disabled", command=changePass)
accountmenu.add_command(label="Add user", command=addUser)
accountmenu.add_command(label="Delete user", state="disabled", command=delUser)
accountmenu.add_command(label="Generate random hash", command=randomHash)
accountmenu.add_command(label="Generate fake password container", command=fake_savefile)

# Tab setup
notebook = ttk.Notebook(root)
tab1 = tk.Frame(notebook, bg='#ADD8E6')
tab2 = tk.Frame(notebook, bg='#ADD8E6')
notebook.add(tab1,text="Passwords", state="disabled")
notebook.add(tab2,text="Notes", state="disabled")
notebook.pack(expand=True,fill="both")

# Widget setup
userLabel = tk.Label(tab1, text=user, font=("Consolas", 10), bg='#ADD8E6')
siteLabel = tk.Label(tab1, text="Site", font=("Consolas", 15), bg='#ADD8E6')
usernameLabel = tk.Label(tab1, text="Username", font=("Consolas", 15), bg='#ADD8E6')
passLabel = tk.Label(tab1, text="Password", font=("Consolas", 15), bg='#ADD8E6')
personalCodeLabel = tk.Label(tab1, text="Code", font=("Consolas", 10), bg='#ADD8E6')
currentSite1 = tk.Entry(tab1, width=20)
currentSite2 = tk.Entry(tab1, width=20)
currentSite3 = tk.Entry(tab1, width=20)
currentSite4 = tk.Entry(tab1, width=20)
currentSite5 = tk.Entry(tab1, width=20)
currentSite6 = tk.Entry(tab1, width=20)
currentSite7 = tk.Entry(tab1, width=20)
currentSite8 = tk.Entry(tab1, width=20)
currentUser1 = tk.Entry(tab1, width=25)
currentUser2 = tk.Entry(tab1, width=25)
currentUser3 = tk.Entry(tab1, width=25)
currentUser4 = tk.Entry(tab1, width=25)
currentUser5 = tk.Entry(tab1, width=25)
currentUser6 = tk.Entry(tab1, width=25)
currentUser7 = tk.Entry(tab1, width=25)
currentUser8 = tk.Entry(tab1, width=25)
currentPass1 = tk.Entry(tab1, width=25, show='*')
currentPass2 = tk.Entry(tab1, width=25, show='*')
currentPass3 = tk.Entry(tab1, width=25, show='*')
currentPass4 = tk.Entry(tab1, width=25, show='*')
currentPass5 = tk.Entry(tab1, width=25, show='*')
currentPass6 = tk.Entry(tab1, width=25, show='*')
currentPass7 = tk.Entry(tab1, width=25, show='*')
currentPass8 = tk.Entry(tab1, width=25, show='*')
personalCode = tk.Entry(tab1, width=5, show='*')
copyBtn1 = tk.Button(tab1, text="Copy", command = lambda: copy_user(1), width=5)
showBtn1 = tk.Button(tab1, text="Show", command = lambda: show(1), width=5)
copyBtn2 = tk.Button(tab1, text="Copy", command = lambda: copy_user(2), width=5)
showBtn2 = tk.Button(tab1, text="Show", command = lambda: show(2), width=5)
copyBtn3 = tk.Button(tab1, text="Copy", command = lambda: copy_user(3), width=5)
showBtn3 = tk.Button(tab1, text="Show", command = lambda: show(3), width=5)
copyBtn4 = tk.Button(tab1, text="Copy", command = lambda: copy_user(4), width=5)
showBtn4 = tk.Button(tab1, text="Show", command = lambda: show(4), width=5)
copyBtn5 = tk.Button(tab1, text="Copy", command = lambda: copy_user(5), width=5)
showBtn5 = tk.Button(tab1, text="Show", command = lambda: show(5), width=5)
copyBtn6 = tk.Button(tab1, text="Copy", command = lambda: copy_user(6), width=5)
showBtn6 = tk.Button(tab1, text="Show", command = lambda: show(6), width=5)
copyBtn7 = tk.Button(tab1, text="Copy", command = lambda: copy_user(7), width=5)
showBtn7 = tk.Button(tab1, text="Show", command = lambda: show(7), width=5)
copyBtn8 = tk.Button(tab1, text="Copy", command = lambda: copy_user(8), width=5)
showBtn8 = tk.Button(tab1, text="Show", command = lambda: show(8), width=5)
copyBtn9 = tk.Button(tab1, text="Copy", command = lambda: copy_password(1), width=5)
copyBtn10 = tk.Button(tab1, text="Copy", command = lambda: copy_password(2), width=5)
copyBtn11 = tk.Button(tab1, text="Copy", command = lambda: copy_password(3), width=5)
copyBtn12 = tk.Button(tab1, text="Copy", command = lambda: copy_password(4), width=5)
copyBtn13 = tk.Button(tab1, text="Copy", command = lambda: copy_password(5), width=5)
copyBtn14 = tk.Button(tab1, text="Copy", command = lambda: copy_password(6), width=5)
copyBtn15 = tk.Button(tab1, text="Copy", command = lambda: copy_password(7), width=5)
copyBtn16 = tk.Button(tab1, text="Copy", command = lambda: copy_password(8), width=5)
notes = tk.Text(tab2)

# Widget placement
userLabel.place(x=30, y=6)
notes.pack(padx=5, pady=5)
siteLabel.place(x=30, y=30)
usernameLabel.place(x=170, y=30)
passLabel.place(x=385, y=30)
currentSite1.place(x=30, y=70)
currentSite2.place(x=30, y=100)
currentSite3.place(x=30, y=130)
currentSite4.place(x=30, y=160)
currentSite5.place(x=30, y=190)
currentSite6.place(x=30, y=220)
currentSite7.place(x=30, y=250)
currentSite8.place(x=30, y=280)
personalCodeLabel.place(x=600, y=10)

if __name__ == '__main__':
    load_userlist()
    root.mainloop()