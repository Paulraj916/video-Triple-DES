import streamlit as st
import base64

st.set_page_config(layout="wide")

def main():
    video_file_path = "path_to_your_decrypted_video_file.mp4"
    video_file = open(video_file_path, "rb")
    video_bytes = video_file.read()
    
    st.header("Download Decrypted Video")
    st.write(f"File: {video_file_path}")
    
    video_b64 = base64.b64encode(video_bytes).decode()
    href = f'<a href="data:video/mp4;base64,{video_b64}" download="{video_file_path}">Click here to download</a>'
    st.markdown(href, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
