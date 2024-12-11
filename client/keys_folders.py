import os

def save_files(keys, tel):
    try:
        if not os.path.exists(tel):
            os.mkdir(tel)
        with open(os.path.join(tel, 'public_key.pem'), 'wb') as f:
            f.write(keys.get_public_pem())
        with open(os.path.join(tel, 'private_key.pem'), 'wb') as f:
            f.write(keys.get_private_pem())
        print("Saved user on folder")
    except Exception as e:
        print(e)


