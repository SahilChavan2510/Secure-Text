import tkinter as tk
from gui import *

if __name__ == "__main__":
    app = tk.Tk()
    app.title("SecureText")
    # Initialize and run the Tkinter GUI
    gui = SecureTextGUI(app)
    app.mainloop()
