import ResourceManager

#set up mock database

r= ResourceManager.ResourceManager()


#test get_username_from_token
d={'users': {'andy': {'password_hash':""}, 'joe': {'password_hash': ""}},
'sessions': {'1234': 'andy'},
'userGroups':{}}
r.write_database(d)

#test get username from token 
assert r.get_username_from_token('1234') == 'andy'

#test create new user group
r.create_new_user_group('1234', "team")
d2= r.read_database()
assert "team" in d2['userGroups']

#test add user to group
r.add_user_to_group('1234', 'team', 'joe', True)
r.add_user_to_group('1234', 'team', 'sally', False)
d3= r.read_database()
assert 'joe' in d3['userGroups']['team']['owners']
assert 'sally' in d3['userGroups']['team']['members']

#test check_user_has_owner_clearance
assert r.check_user_has_owner_clearance('andy', 'team')
assert r.check_user_has_owner_clearance('joe', 'team')
assert r.check_user_has_owner_clearance('sally', 'team')==False


#test check_user_has_read_clearance

assert r.check_user_has_read_clearance('andy', 'team')==True
assert r.check_user_has_read_clearance('joe', 'team')==True
assert r.check_user_has_read_clearance('sally', 'team')==True

#test remove user from group
r.remove_user_from_group('1234', 'team', 'joe')
d4= r.read_database()
assert 'joe' not in d4['userGroups']['team']['owners']


#test list_user_groups
r.create_new_user_group('1234', "team2")
d5= r.read_database()
user_groups = r.list_user_groups('1234')
assert "team" in user_groups and "team2" in user_groups


#test delete_user_groups
r.delete_user_group('1234', "team2")
d6= r.read_database()
user_groups= r.list_user_groups('1234')
assert "team2" not in user_groups


