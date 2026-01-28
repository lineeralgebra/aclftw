from ldap3 import Server, ALL, Connection, NTLM, SUBTREE
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_ALLOWED_ACE
from uuid import UUID
import argparse

#https://learn.microsoft.com/en-us/windows/win32/secauthz/generic-access-rights

GENERIC_ALL = 0x10000000
FULL_CONTROL_AD = 0x000f01ff
#DOMAIN_DN = 'DC=sansar,DC=local'
#victim_user = 'osman'
#target_user = 'irem' 

def infer_netbios(domain):
	return domain.split('.')[0].upper()

def domain_to_dn(domain):
	return ','.join(f'DC={x}' for x in domain.split('.'))

def main():
	parser = argparse.ArgumentParser(description='Enum ACL')
	parser.add_argument('-u', '--username', required=True, help='Username of victim')
	parser.add_argument('-p', '--password', required=True, help='Password of victim')
	parser.add_argument('-d', '--domain', required=True, help='domain')
	parser.add_argument('-dc-ip', '--dc-ip', required=True, help='domain')

	args = parser.parse_args()
	netbios = infer_netbios(args.domain)
	base_dn = domain_to_dn(args.domain)

	server = Server(args.dc_ip, get_info=ALL)
	try:
		conn = Connection(server, user=f"{netbios}\\{args.username}", password=args.password, authentication=NTLM, auto_bind=True)
		#conn.search(DOMAIN_DN, f'(sAMAccountName={victim_user})', attributes=['objectSid'])
	except Exception as e:
		print(f"[-] Auth failed!: {e}")
		return
	print(f"[+] Connection Success!")
#print(conn.entries)

	conn.search(base_dn, f'(sAMAccountName={args.username})', attributes=['objectSid'])

	if not conn.entries:
		print(f"[-] Could not find: {args.username}")
		return

	victim_sid = LDAP_SID(conn.entries[0].objectSid.raw_values[0]).formatCanonical() # why its connecting Administrator?
	print(f"Resolved victim_sid: {victim_sid}") #now its give victim user

	#time to search all things
	user_filter = '(&(objectClass=person)(objectClass=user))'
	controls = [('1.2.840.113556.1.4.801', True, b'\x30\x03\x02\x01\x07')]
	conn.search(base_dn, user_filter, attributes=['sAMAccountName', 'nTSecurityDescriptor'], controls=controls)
	#if not conn.entries:
		#print(f"[-] Could not find: {target_user}")
		#exit()

	found_any = False

	for entry in conn.entries:
		target_name = entry.sAMAccountName

		if str(target_name).lower() == args.username.lower():
			continue
		if 'nTSecurityDescriptor' not in entry:
			continue
		sd = SR_SECURITY_DESCRIPTOR(data=entry.nTSecurityDescriptor.raw_values[0])

		for ace in sd['Dacl'].aces:
			try:
				trustee_sid = ace['Ace']['Sid'].formatCanonical()
				mask = ace['Ace']['Mask']['Mask']


				if trustee_sid == victim_sid:

					if (mask & GENERIC_ALL) or (mask & FULL_CONTROL_AD):
						print(f"Victim ({args.username}) has GENERIC_ALL on: {target_name}")
						print(f"Access Mask: {hex(mask)}")
						found_any = True
			except:
				continue
	if not found_any:
		print('nothing')
if __name__ == "__main__":
	main()
