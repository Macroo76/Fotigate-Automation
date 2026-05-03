# Fotigate-Automation

this tool will automate the Remote Disktop access VPN in fortigate firewall it includes
1_creating the IP POOL for the VPN Clients if not exists
2_adding the adress group for the destinations if not exists
3_it creates the user group for the xauth 
4_it automatically adds the nessary policies for the Phase2

it uses API token for the auth and for security the API token should be increpted and stored using windows Credential Manager under the name FGT_API using the following cmd command:
cmd >>>>>>>>>   cmdkey /add:FGT_API /user:anything /pass:YOUR_API_TOKEN

