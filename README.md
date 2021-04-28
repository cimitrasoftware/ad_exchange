# ad_exchange
38 Common Actions For Active Directory and Exchange User Accounts

This script allows for dozens of modifications you can make to Active Directory and Exchange User accounts. For example, you can create a user in Active Directory or Exchange, and set several of their attributes at the time of the user creation event. 

Or you can modify only one or some attributes of an existing Active Directory or Exchange User account. 

Here is how you could create a user in Active Directory, and add several attributes to that user. 

.\cimitra_ad_exchange.ps1 -AddToActiveDirectory -FirstName "Bob" -LastName "Jones" -ContextIn "OU=ADMINISTRATION,OU=DEMOUSERS,DC=cimitrademo,DC=com" -SamAccountName "bjones" -Title "Controller" -DefaultPassword "abc_4242" -ManagerFirstName "Steve" -ManagerLastName "McQueen" -ManagerContext "OU=ADMINISTRATION,OU=DEMOUSERS,DC=cimitrademo,DC=com" -Description "Accounting Department Employee" -OfficePhone "801-111-2222" -MobilePhone "801-333-3333" -ExpirationDate "02/20/2035"

Tested and developed on a Windows 2016 and Windows 2019 Server
Initially released on April 28th, 2021

Here are the actions you can take with this script. 

1. Add User to Active Directory
2. Add User to Exchange
3. Rename Active Directory User's SamAccountName
4. Change Exchange User's First Name
5. Change Exchange User's Last Name
6. Change Active Directory User's First Name
7. Change Active Directory User's Last Name
8. Modify Active Directory User's Mobile Phone Number
9. Modify Active Directory User's Office Phone Number
10. Modify Active Directory User's Title
11. Modify Active Directory User's Description
12. Modify Active Directory User's Manager
13. Modify Active Directory User's Department
14. Add an Active Directory User to an Active Directory Group by the Group GUID
15. Add an expiration date to an Active Directory User account
16. Remove the expiration date from an Active Directory User account
17. Enable an Active Directory User account
18. Disable an Active Directory User account
19. Unlock an Active Directory User account
20. Determine which Active Directory User accounts are in a locked state
21. Change the Password on an Active Directory User account
22. Check the Password change date on an Active Directory User account
23. Get account access info on an Active Directory User account
24. Get a report of several attributes on an Active Directory User account
25. Find all information about an Active Directory Group
26. List all users in an Active Directory tree
27. List all Users in a certain context in an Active Directory tree
28. List all Disabled Users in an Active Directory tree
29. List all Disabled Users in an Active Directory tree context
30. List all Expired Users in an Active Directory tree
31. List all Expired Users in an Active Directory tree context
32. List all Users in an Active Directory tree who have not logged in
33. List all Users in an Active Directory tree context who have not logged in
34. List all Users in an Active Directory tree who are locked out
35. Remove an Active Directory User from an Active Directory Group by Group GUID
36. Remove an Active Directory User from a comma-separted list of Active Directory Groups by Group GUID
37. Add an Active Directory User to a comma-separated list of Active Directory Groups by Group GUID
38. Remove an Active Directory user

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

DEPENDENCIES

The cimitra_ad_exchange.ps1 script has a dependency upon two other scripts: 

config_reader.ps1
SearchForUser.ps1

These scripts should be located in the same directory as the cimitra_ad_exchange.ps1 script. 

EXCHANGE ACCOUNT CREATION AND CHANGES

In order to create an Exchange Session this script requires several different inputs. For example, an encrypted password file is required. Or the Exchange domain URI. Here are examples for the required switches in order to create a user in Exchange: 

-AddToExchange -ExchangeSecurePasswordFileIn "C:\Cimitra\Scripts\CimAgentPwd.txt"  -ExchangeConnectionURIIn "http://ACME-EXCH16.acme.internal/PowerShell/" -ExchangeDomainNameIn "acme.biz" -CimitraAgentLogonAccountIn "CimitraAgent@acme.biz" -FirstName "John" -LastName "Doe" -ContextIn "OU=ADMINISTRATION,OU=DEMOUSERS,DC=cimitrademo,DC=com"

In order to encrypt the password file needed for the -ExchangeSecurePasswordFileIn switch, see this article by Adam Bertram:
https://4sysops.com/archives/encrypt-a-password-with-powershell/

The ExchangePowerShell module from Microsoft must be installed in order to add and change Exchange User accounts. 
