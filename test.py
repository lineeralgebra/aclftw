from ldap3 import Server, ALL, Connection, NTLM, SUBTREE
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID
from uuid import UUID

# 1. Connect
# 2. Search for target user
# 3. Get nTSecurityDescriptor
# 4. Parse with SR_SECURITY_DESCRIPTOR
# 5. Loop through ACEs
# 6. For each ACE: print SID, mask, permissions
server = Server('sansar.local', get_info=ALL)
conn = Connection(server, 'SANSAR\\abby.gates', 'Password123', auto_bind=True)
conn.search('DC=sansar,DC=local', '(objectclass=user)', attributes=['sAMAccountName'])

#print(conn.entries)

for entry in conn.entries:
	print(entry.sAMAccountName)