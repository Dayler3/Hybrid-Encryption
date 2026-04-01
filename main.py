import os
from src.gui import App


def setup():
    for d in ["data/encrypted", "data/decrypted", "keys"]:
        os.makedirs(d, exist_ok=True)


if __name__ == "__main__":
    setup()
    app = App()
    app.mainloop()
