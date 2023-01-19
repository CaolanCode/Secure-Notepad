# Secure-Notepad

A notepad with the below functionality:

1. Creates a file
2. Saves the file encrypted using AES from the [Bouncy Castle](https://www.bouncycastle.org/java.html) Cryptography API
3. Encrypts using a password
4. Decrypts the file when opened with the application using the correct password
5. If the password entered is incorrect, brute force attack the file using a password list provided


