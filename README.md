# ad_exchange
40 Common Actions For Active Directory and Exchange User Accounts

Tested and developed on a Windows 2016 and Windows 2019 Server
Initially released on April 27th, 2021

1. Add User to Active Directory
2. Add User to Exchange
3. Rename Active Directory User's SamAccountName
4. Change Exchange User's First Name
5. Change Exchange User's Last Name
6. Change Active Directory User's First Name
7. Change Active Directory User's Last Name
8. Change Exchange User's First Name
9. Change Exchange User's Last Name
10. Modify Active Directory User's Mobile Phone Number
11. Modify Active Directory User's Office Phone Number
12. Modify Active Directory User's Title
13. Modify Active Directory User's Description
14. Modify Active Directory User's Manager
15. Modify Active Directory User's Department
16. Add an Active Directory User to Active Directory Group by the Group GUID
17. Add an expiration date to an Active Directory User account
18. Remove an expiration date from an Active Directory User account
19. Enable an Active Directory User account
20. Disable an Active Directory User account
21. Unlock an Active Directory User account
22. Determine which Active Directory User accounts are in a locked state
23. Change the Password on an Active Directory User account
24. Check the Password change date on an Active Directory User account
25. Get account access info on an Active Directory User account
26. Get a report of several attributes on an Active Directory User account
27. Find all information about an Active Directory Group
28. List all users in an Active Directory tree
29. List all Users in a certain context in an Active Directory tree
30. List all Disabled Users in an Active Directory tree
31. List all Disabled Users in an Active Directory tree context
32. List all Expired Users in an Active Directory tree
33. List all Expired Users in an Active Directory tree context
34. List all Users in an Active Directory tree who have not logged in
35. List all Users in an Active Directory tree context who have not logged in
36. List all Users in an Active Directory tree who are locked out
37. Remove an Active Directory User from an Active Directory Group by Group GUID
38. Remove an Active Directory User from a comma separted list of Active Directory Groups by Group GUID
39. Add an Active Directory User to a comma separated list of Active Directory Groups by Group GUID
40. Remove an Active Directory user. 

ADDITIONAL FUNCTIONALITY

[ USER SEARCH ]

When you specify a user by their First and Last name, but don't specify the user's context, this script will search for users with the First and Last names specified. If only one user is found with that First and Last name, then that user is modified. 

If there are two users with the same First and Last name, then the script will list both users and will not proceed. 

[DEFAULT CONTEXT]

The "Default Context" can be specified in a configuration file called "settings.cfg". The Default Context setting in the settings.cfg file looks like this: 

AD_USER_CONTEXT=OU=DEMOUSERS,OU=DEMO,DC=cimitrademo,DC=com

[EXCLUDE GROUP]

Users defined in a group designated as the "Exclude Group" cannot be modified by this script. The "Exclude Group" can be specified in a configuration file called "settings.cfg". The Exclude Group setting in the settings.cfg file looks like this: 

AD_EXCLUDE_GROUP=35eddbe6-234f-4f94-af4c-efb0198e4247

The cimitra_ad_exchange.ps1 script has a dependency upon two other scripts: 

config_reader.ps1
SearchForUser.ps1

These scripts should be located in the same directory as the cimitra_ad_exchange.ps1 script. 
