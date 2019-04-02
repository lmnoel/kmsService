echo "Running create new user"
echo "Input a Username + Password when prompted"
echo "Example: AlphaBravo and AlphaBravo1!"
echo "Remember these credentials as they are required for validation"
echo ""
echo "python3 client.py --create_user"
python3 client.py --create_user
echo ""

echo "Encrypting a file"
echo "The README.md file will be encrypted"
echo "Input the credentials from the previous command when prompted"
echo ""
echo "python3 client.py --encrypt -f README.md -o cipherREADME.cipher"
python3 client.py --encrypt -f README.md -o cipherREADME.cipher

echo ""
echo "Decrypting a file"
echo "The cipher for README.md will be decrypted"
echo "Input the user credentials when prompted"
echo ""
echo "python3 client.py --decrypt -f cipherREADME.cipher -o decryptedREADME.md"
python3 client.py --decrypt -f cipherREADME.cipher -o decryptedREADME.md

echo ""
echo "The file decryptedREADME.md should now be a copy of the original README"
