import streamlit as st
from Crypto.Cipher import DES
from Crypto.Hash import SHA256
from getpass import getpass
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from io import BytesIO

Key_length = 100005
salt = "$ez*&214097GDAKACNASC;LSOSSBAdjskasnmosuf!@#$^()_adsa"

def encrypt_video(video_data, password):
    try:
        # Hashing original video in SHA256
        hash_of_original = SHA256.new(data=video_data)
        
        # Inputting Keys
        key_enc = password
        
        # Salting and hashing password
        key_enc = PBKDF2(key_enc, salt, 48, Key_length)
        
        # Pad the input data to meet the block size requirement
        padded_video = pad(video_data, DES.block_size)
        
        # Encrypting using triple 3 key DES	
        st.write("Wait it is being encrypting.....\n")
        try:
            cipher1 = DES.new(key_enc[0:8], DES.MODE_CBC, key_enc[24:32])
            ciphertext1 = cipher1.encrypt(padded_video)
            cipher2 = DES.new(key_enc[8:16], DES.MODE_CBC, key_enc[32:40])
            ciphertext2 = cipher2.encrypt(ciphertext1)
            cipher3 = DES.new(key_enc[16:24], DES.MODE_CBC, key_enc[40:48])
            ciphertext3 = cipher3.encrypt(ciphertext2)
            
            st.write("\n------ENCRYPTION SUCCESSFUL-------")
        except Exception as e:
            st.error("Encryption failed... Possible causes: " + str(e))
            return
        
        # Adding hash at end of encrypted bytes
        ciphertext3 += hash_of_original.digest()
        
        st.write("\n------ENCRYPTION SUCCESSFUL-------")
        return ciphertext3

def decrypt_video(encrypted_data, password):
    try:
        # Key Authentication
        key_dec = password

        # Extracting hash and cipher data without hash
        extracted_hash = encrypted_data[-32:]
        encrypted_data = encrypted_data[:-32]

        # Salting and hashing password
        key_dec = PBKDF2(key_dec, salt, 48, Key_length)

        # Decrypting using triple 3 key DES
        st.write("Decrypting...")
        try:
            cipher3 = DES.new(key_dec[16:24], DES.MODE_CBC, key_dec[40:48])
            decrypted_data3 = cipher3.decrypt(encrypted_data)
            cipher2 = DES.new(key_dec[8:16], DES.MODE_CBC, key_dec[32:40])
            decrypted_data2 = cipher2.decrypt(decrypted_data3)
            cipher1 = DES.new(key_dec[0:8], DES.MODE_CBC, key_dec[24:32])
            decrypted_data1 = cipher1.decrypt(decrypted_data2)

        except Exception as e:
            st.error("Decryption failed... Possible causes: " + str(e))
            return

        # Unpad the decrypted data
        decrypted_video = unpad(decrypted_data1, DES.block_size)

        # Hashing decrypted plain text
        hash_of_decrypted = SHA256.new(data=decrypted_video)

        # Matching hashes
        if hash_of_decrypted.digest() == extracted_hash:
            st.success("Decryption successful!")
            return decrypted_video
        else:
            st.error("Incorrect Password!!!!!")
            return None
    except Exception as e:
        st.error("Decryption failed: " + str(e))
        return None

def main():
    st.title("Triple DES Video Encryption and Decryption")

    choice = st.radio("Choose an option:", ("Encrypt", "Decrypt"))

    if choice == "Encrypt":
        video_file = st.file_uploader("Upload a video to encrypt", type=["mp4"])
        password = st.text_input("Enter minimum 8 character long password:", type="password")
        if st.button("Encrypt"):
            if video_file and len(password) >= 8:
                video_data = video_file.read()
                encrypted_data = encrypt_video(video_data, password)
                if encrypted_data:
                    st.success("Encryption successful!")
                else:
                    st.error("Encryption failed.")
            else:
                st.warning("Please provide a video file and a password of at least 8 characters.")
    
    elif choice == "Decrypt":
        encrypted_video_file = st.file_uploader("Upload an encrypted video to decrypt", type=["mp4"])
        password = st.text_input("Enter password:", type="password")
        
        if st.button("Decrypt"):
            if encrypted_video_file and password:
                encrypted_data = encrypted_video_file.read()
                decrypted_data = decrypt_video(encrypted_data, password)
                if decrypted_data:
                    st.success("Decryption successful!")
                else:
                    st.error("Decryption failed.")
                    
if __name__ == "__main__":
    main()
