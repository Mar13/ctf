#!/usr/bin/env python
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from secret import key, flag, passwd
import json

BLOCK_LENGTH = 16


def check_pad(s, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    t = cipher.decrypt(s)
    try:
        unpad(t, BLOCK_LENGTH)
        return True
    except:
        return False


def get_pass():
    iv = os.urandom(BLOCK_LENGTH)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    enc_passwd = cipher.encrypt(pad(passwd, BLOCK_LENGTH))
    return json.dumps({"passwd": enc_passwd.hex(), "iv": iv.hex()})


def verify_passwd(your_pass):
    if your_pass == str(passwd):
        data = json.dumps({"flag": flag})
        return data
    else:
        return "incorrect passwd"


def option_check(text, iv):
    try:
        return check_pad(bytes.fromhex(text), bytes.fromhex(iv))
    except:
        return "need hex format"


def header():
    print("Здравствуйте, дорогие работяги, я украл у вас что-то очень нужное\n"
          "Сегодня у меня хорошее настроение и вы можете получить эту ценную информацию, но только в зашифрованном виде :)\n"
          "Также вы можете ввести ваш шифр и проверить его. Ваши опции:\n")


def print_options():
    print("check - проверить padding шифротекста в JSON формате в hex кодировке\n"
          "get_pass - получить зашифрованное сообщение в hex формате\n"
          "verify_passwd - ввести пароль и получить флаг\n")


def main():
    header()
    while True:
        print_options()
        try:
            choice = json.loads(input())
            if choice["option"] == "get_pass":
                server_answer = get_pass()
                print(server_answer)
            elif choice["option"] == "verif_passwd":
                server_answer = verify_passwd(choice["passwd"])
                print(server_answer)
            elif choice["option"] == "check":
                server_answer = option_check(choice["text"], choice["iv"])
                print(server_answer)
            else:
                print("Bad input")
        except:
            print("Incorrect JSON")


if __name__ == "__main__":
    main()
