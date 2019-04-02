echo "Running create new user"
echo "Input a Username + Password when prompted"
echo "Example: Alpha and AlphaBravo1!"
echo "This user will be refered to as user 1"
echo "Remember these credentials as they are required for validation"
echo ""
echo "python3 client.py --create_user"
python3 client.py --create_user
echo ""

echo "Now creating a second user to add/remove from our groups"
echo "Input a new Username when prompted"
echo "Example: Bravo and AlphaBravo1!"
echo "This user will be refered to as user 2"
echo "Remember these credentials as they are required for validation"
echo ""
echo "python3 client.py --create_user"
python3 client.py --create_user
echo ""

echo "Running create group"
echo "The group Alphabetical will be created"
echo "Input the credentials for user 1 when prompted"
echo ""
echo "python3 client.py --create_group -group Alphabetical"
python3 client.py --create_group -group Alphabetical
echo ""

echo "Running add user to group"
echo "user 2 will be added to Alphabetical"
echo "Input the credentials for user 1 when prompted"
echo "Then input the name of user 2 when prompted"
echo ""
echo "python3 client.py --add_user -group Alphabetical"
python3 client.py --add_user -group Alphabetical
echo ""

echo "Running list members"
echo "This will show the members of Alphabetical"
echo "Input the credentials for user 1 when prompted"
echo ""
echo "python3 client.py --list_members -group Alphabetical"
python3 client.py --list_members -group Alphabetical
echo ""

echo "Running list groups"
echo "python3 client.py --list_groups"
echo "This will show the groups user 1 or 2 is a member of"
echo "Input the credentials for user 1 or 2 when prompted"
echo ""
python3 client.py --list_groups
echo ""

echo "Running remove user"
echo "This will remove user 2 from the group Alphabetical"
echo "Input the credentials for user 1 when prompted"
echo "Then input the username for user 2"
echo ""
echo "python3 client.py --remove_user -group Alphabetical"
python3 client.py --remove_user -group Alphabetical
echo ""

echo "Re-Running list members"
echo "This will show that user 2 has been removed from Alphabetical"
echo "Input the credentials for user 1 when prompted"
echo ""
echo "python3 client.py --list_members -group Alphabetical"
python3 client.py --list_members -group Alphabetical
echo ""

echo "Running remove group"
echo "This will remove the group Alphabetical"
echo "Input the credentials for user 1 when prompted"
echo ""
echo "python3 client.py --remove_group -group Alphabetical"
python3 client.py --remove_group -group Alphabetical
echo ""

echo "re-Running list groups"
echo "This will show that Alphabetical has been removed"
echo "Input the credentials for user 1 when prompted"
echo ""
echo "python3 client.py --list_groups"
python3 client.py --list_groups
echo ""



