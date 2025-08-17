import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from secret import FLAG, prefix, secret, secret2
import jwt

rand = get_random_bytes(16)

def pce(str):
    iv = get_random_bytes(16)

    spce = (
        f"name={str}_{prefix * random.randint(1, 100)};uid={random.randint(1,10000000)}"
    )
    bpce = bytes(spce, "utf-8")
    p = pad(bpce, 16)
    c = AES.new(secret2, AES.MODE_CBC, iv)
    e = c.encrypt(p)

    return f"{e.hex()}+{iv.hex()}+{rand.hex()}"


def pce_decrypt(enc):
    e = bytes.fromhex(enc[0])
    iv = bytes.fromhex(enc[1])

    c = AES.new(secret2, AES.MODE_CBC, iv)
    d = c.decrypt(e)

    return unpad(d, AES.block_size).decode("utf-8")


def register(name):
    token = pce(name)

    data = {
        "name": name,
        "user_id": random.randint(1, 100),
        "token": token,
    }

    cookie = jwt.encode(data, secret, algorithm="HS256")
    print("Store this cookie for login:", cookie)


def login(name, cookie):
    decoded = jwt.decode(cookie, secret, algorithms=["HS256"])

    if decoded["name"] != name:
        print("Whoops! This cookie is not for you.")
        return

    if decoded["name"] == "admin":
        print(pce_decrypt(decoded["token"].split("+")))
        if (
            decoded["name"]
            == pce_decrypt(decoded["token"].split("+")).split(";")[0].split("=")[1]
            and rand.hex() == decoded["token"].split("+")[2]
        ):
            print("GG, here your flag: ", FLAG)
            return
        else:
            print("Whoops! This cookie is not for you.")

    print("Welcome back, " + decoded["name"] + "!")


if __name__ == "__main__":
    print("=" * 30)
    print("Welcome to the Super Secure Login System")
    print("=" * 30)

    while True:
        print("\nMenu:")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Enter your choice (1/2/3): ")

        if choice == "1":
            name = input("Enter your name: ")
            if name == "admin":
                print("You cannot register as admin.")
            else:
                register(name)

        elif choice == "2":
            name = input("Enter your name: ")
            cookie = input("Enter your cookie: ")
            login(name, cookie)

        elif choice == "3":
            print("Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")
