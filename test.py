from ldap3 import Server, ALL, Connection, NTLM, SUBTREE
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_ALLOWED_ACE
from uuid import UUID
import argparse

#https://learn.microsoft.com/en-us/windows/win32/secauthz/generic-access-rights
#https://www.0xczr.com/tools/ACL_cheatsheet/
#https://www.0xczr.com/tools/ACL_cheatsheet/#complete-acl-attack-matrix
GENERIC_ALL = 0x10000000
FULL_CONTROL_AD = 0x000f01ff
GENERIC_WRITE = 0x40000000
WRITE_OWNER = 0x00080000
WRITE_DACL = 0x00040000
CONTROL_ACCESS = 0x00000100
#DOMAIN_DN = 'DC=sansar,DC=local'
#victim_user = 'osman'
#target_user = 'irem' 

SPN_GUID = UUID("f3a64788-5306-11d1-a9c5-0000f80367c1")
User_Force_Change_Password = UUID("00299570-246d-11d0-a768-00aa006e0529")
DS_Replication_Get_Changes = UUID("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
DS_Replication_Get_Changes_All = UUID("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
Self_Membership = UUID("bf9679c0-0de6-11d0-a285-00aa003049e2")
#GMSA_PASSWORD_GUID = UUID("3ed48e12-8273-11d2-8da6-0000f8759a0f")
GMSA_PASSWORD_GUID = UUID("e362ed86-b728-0842-b27d-2dea7a9df218")  # msDS-ManagedPassword
GMSA_PASSWORD_GUID_ALT = UUID("{e362ed86-b728-0842-b27d-2dea7a9df218}")
def infer_netbios(domain):
    return domain.split('.')[0].upper()

def domain_to_dn(domain):
    return ','.join(f'DC={x}' for x in domain.split('.'))

#def users_to_groups(conn, base_dn, username):
    #conn.search(base_dn, f'(sAMAccountName={username})', attributes=['memberOf'])
    #if not conn.entries:
        #return [] # it will give nothing inside of member
    #groups = []

    #if hasattr(conn.entries[0], 'memberOf'):
        #for group_dn in conn.entries[0].memberOf.values:
            #groups.append(str(group_dn))
    #return groups
def users_to_groups(conn, base_dn, username):
    search_filter = f"(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={base_dn.replace('DC=', 'CN=' + username + ',CN=Users,')}))"

    conn.search(base_dn, f'(sAMAccountName={username})', attributes=['distinguishedName'])
    if not conn.entries:
        return []
    user_dn = conn.entries[0].distinguishedName.value

    conn.search(base_dn, f'(member:1.2.840.113556.1.4.1941:={user_dn})', attributes=['distinguishedName'])

    groups = [str(entry.distinguishedName) for entry in conn.entries]
    return groups

def get_groups_sids(conn, base_dn, group_dns):
    groups_sids = {}

    for group_dn in group_dns:
        try:
            conn.search(group_dn, '(objectClass=group)', attributes=['sAMAccountName', 'objectSid'], search_scope='BASE')

            if conn.entries and hasattr(conn.entries[0], 'objectSid'):
                sid_bytes = conn.entries[0].objectSid.raw_values[0]
                sid = LDAP_SID(sid_bytes).formatCanonical()
                group_name = str(conn.entries[0].sAMAccountName)
                groups_sids[sid] = group_name
        except Exception:
            continue
    
    return groups_sids

def decode_mask(mask):
    rights = []

    if (mask & 0xf01ff) == 0xf01ff or (mask & GENERIC_ALL):
        return ["Full Control / Generic All"]
    
    #if mask & GENERIC_WRITE:
        #rights.append("Generic Write")
    generic_write_mapped = 0x20028
    if (mask & GENERIC_WRITE) or ((mask & generic_write_mapped) == generic_write_mapped):
        rights.append("Generic Write")

    if mask & WRITE_DACL:
        rights.append("Write DACL (Modify Permissions)")
        
    if mask & WRITE_OWNER:
        rights.append("Write Owner (Take Ownership)")

    if mask & 0x00000100:
        rights.append("Extended Rights (Control Access)")

    #if mask & 0x00000010:
        #rights.append("Write Property")

    if mask & 0x00000001:
        rights.append("Create Child")

    return rights
def main():
    parser = argparse.ArgumentParser(description='Enum ACL')
    parser.add_argument('-u', '--username', required=True, help='Username of victim')
    parser.add_argument('-p', '--password', help='Password of victim')
    parser.add_argument('-d', '--domain', required=True, help='domain')
    parser.add_argument('-dc-ip', '--dc-ip', required=True, help='domain')
    parser.add_argument('-H', '--hash', help='NTLM hash (for PTH)')

    args = parser.parse_args()
    netbios = infer_netbios(args.domain)
    base_dn = domain_to_dn(args.domain)

    server = Server(args.dc_ip, get_info=ALL)
    try:
        if args.hash:
            lm = "aad3b435b51404eeaad3b435b51404ee"
            nt = args.hash
            conn = Connection(server, user=f"{netbios}\\{args.username}", password=f"{lm}:{nt}", authentication=NTLM, auto_bind=True)
        else:
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
    #print(f"Resolved victim_sid: {victim_sid}") #now its give victim user

    victim_groups = users_to_groups(conn, base_dn, args.username)
    groups_sids = get_groups_sids(conn, base_dn, victim_groups)
    #groups_sids = LDAP_SID(conn.entries[0].objectSid.raw_values[0]).formatCanonical()
    #victim_groups = users_to_groups(conn, base_dn, victim_groups)
    #time to search all things
    print(f"\n[DEBUG] Groups for {args.username}:")
    for sid, name in groups_sids.items():
        print(f"  - {name} ({sid})")
    print()

    #if groups_sids:
        #for sid, name in groups_sids.items():
            #print(f"-{name} ({sids})")

    all_victim_sids = {victim_sid: f"{args.username} (direct)"}
    #all_victim_sids.append(groups_sids)

    for sid, name in groups_sids.items():
        all_victim_sids[sid] = f"{name} (group)"
    #user_filter = '(&(objectClass=person)(objectClass=user))'
    controls = [('1.2.840.113556.1.4.801', True, b'\x30\x03\x02\x01\x07')]
    principal_filter = '(|(objectClass=user)(objectClass=group)(objectClass=computer)(objectClass=msDS-GroupManagedServiceAccount)(objectClass=organizationalUnit))'
    #principal_filter = '(|(objectClass=user)(objectClass=group)(objectClass=computer)(objectClass=msDS-GroupManagedServiceAccount))'
    #principal_filter = '(|(objectClass=user)(objectClass=group)(objectClass=computer))'
    #principal_filter = '(|(objectClass=user)(objectClass=group)(objectClass=computer)(objectClass=msDS-GroupManagedServiceAccount))'
    conn.search(base_dn, principal_filter, attributes=['sAMAccountName', 'nTSecurityDescriptor', 'objectClass'], controls=controls)
    #if not conn.entries:
        #print(f"[-] Could not find: {target_user}")
        #exit()
   # print("\n[DEBUG] Checking for GMSA accounts.....")
    #for entry in conn.entries:
        #if hasattr(entry, 'objectClass'):
            #obj_classes = entry.objectClass.values
            #if "msDS-GroupManagedServiceAccount" in obj_classes:
                #print(f"Found GMSA: {entry.sAMAccountName}")
    #print("[DEBUG] Done checking GMSAs\n")
    found = False # never delete this!!!!!!!!!!!!!!!!

    for entry in conn.entries:
        if not entry.sAMAccountName or 'nTSecurityDescriptor' not in entry:
            continue
        #target_name = entry.sAMAccountName
        target_name = str(entry.sAMAccountName)
        if target_name.lower() == args.username.lower():
            continue
        #if str(target_name).lower() == args.username.lower():
            #continue
        #if 'nTSecurityDescriptor' not in entry:
            #continue
        #sd = SR_SECURITY_DESCRIPTOR(data=entry.nTSecurityDescriptor.raw_values[0])

        obj_classes = entry.objectClass.values if hasattr(entry, 'objectClass') else []
        obj_type = "user"
        if "computer" in obj_classes:
            obj_type = "computer"
        elif "group" in obj_classes:
            obj_type = "group"
        elif "msDS-GroupManagedServiceAccount" in obj_classes:
            obj_type = "gmsa"
        elif "organizationalUnit" in obj_classes:
            obj_type = "ou"

        #for ace in sd['Dacl'].aces:
            #try:
                #trustee_sid = ace['Ace']['Sid'].formatCanonical()
                #mask = ace['Ace']['Mask']['Mask']
        try:
            sd = SR_SECURITY_DESCRIPTOR(data=entry.nTSecurityDescriptor.raw_values[0])
        except Exception:
            continue

        if not sd['Dacl']:
            continue
        for ace in sd['Dacl'].aces:
            
            # --- GUID Extraction logic for Object ACEs ---
            try:
                trustee_sid = ace['Ace']['Sid'].formatCanonical()
                mask = ace['Ace']['Mask']['Mask']
            except:
                continue

            if trustee_sid not in all_victim_sids:
                continue

            ace_found = False

            #WriteSPN detection
            if ace['AceType'] in [ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE]:
                # Using ACE_OBJECT_TYPE_PRESENT instead of ADS_FLAG_OBJECT_TYPE_PRESENT
                if ace['Ace']['Flags'] & ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT:
                    try:
                        obj_guid = UUID(bytes_le=ace['Ace']['ObjectType'])
                        if obj_guid == SPN_GUID:
                            src = "DIRECT" if trustee_sid == victim_sid else "VIA GROUP"
                            via = all_victim_sids[trustee_sid]
                            print(f"[{src}] {args.username} -> {target_name} ({obj_type})")
                            print(" Rights: WriteSPN")
                            print(f" Mask: {hex(mask)}")
                            print(f" Via: {via}")
                            print("-" * 20)
                            found = True
                            ace_found = True
                    except Exception:
                        pass
            #WriteSPN detection end
            #forcechangepassword detection
            if ace['AceType'] in [ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE]:
                if ace['Ace']['Flags'] & ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT:
                    try:
                        obj_guid = UUID(bytes_le=ace['Ace']['ObjectType'])
                        if obj_guid == User_Force_Change_Password:
                            src = "DIRECT" if trustee_sid == victim_sid else "VIA GROUP"
                            via = all_victim_sids[trustee_sid]
                            print(f"[{src}] {args.username} -> {target_name} ({obj_type})")
                            print("Rights: User_Force_Change_Password")
                            print(f"Mask: {hex(mask)}")
                            print(f"Via: {via}")
                            print("-" * 20)
                            found = True
                            ace_found = True
                    except Exception:
                        pass
            # Addself detection
            if ace['AceType'] in [ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE]:
                if ace['Ace']['Flags'] & ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT:
                    try:
                        obj_guid = UUID(bytes_le=ace['Ace']['ObjectType'])
                        if obj_guid == Self_Membership:
                            src = "DIRECT" if trustee_sid == victim_sid else "VIA GROUP"
                            via = all_victim_sids[trustee_sid]
                            print(f"[{src}] {args.username} -> {target_name} ({obj_type})")
                            print("Rights: AddSelf (Self-Membership)")
                            print(f"Mask: {hex(mask)}")
                            print(f"Via: {via}")
                            print("-" * 20)
                            found = True
                            ace_found = True
                    except Exception:
                        pass
            if not ace_found and ace['AceType'] == ACCESS_ALLOWED_ACE.ACE_TYPE:
                if (mask & 0x00000008) and obj_type == "group":
                    src = "DIRECT" if trustee_sid == victim_sid else "VIA GROUP"
                    via = all_victim_sids[trustee_sid]
                    print(f"[{src}] {args.username} -> {target_name} ({obj_type})")
                    print("Rights: AddSelf(Self-Membership) - via SELF bit")
                    print(f"Mask: {hex(mask)}")
                    print(f"Via: {via}")
                    print("-" * 20)
                    found = True
                    ace_found = True 
            # addself end
            # GMSA
            #if not ace_found and obj_type == "gmsa":
            #if not ace_found and ace['AceType'] == ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                #if ace['AceType'] == ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                    #if ace['Ace']['Flags'] & ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT:
                        #try:
                            #obj_guid = UUID(bytes_le=ace['Ace']['ObjectType'])
                            #if obj_guid == GMSA_PASSWORD_GUID:
                                #src = "DIRECT" if trustee_sid == victim_sid else "VIA GROUP"
                                #via = all_victim_sids[trustee_sid]
                                #print(f"[{src}] {args.username} -> {target_name} ({obj_type})")
                                #print("Rights: ReadGMSAPassword")
                                #print(f"Mask: {hex(mask)}")
                                #print(f"Via: {via}")
                                #print("-" * 20)
                                #found = True
                                #ace_found = True
                        #except Exception:
                            #pass
            #if not ace_found and ace['AceType'] == ACCESS_ALLOWED_ACE.ACE_TYPE:
                #if mask & CONTROL_ACCESS:
                    #src = "DIRECT" if trustee_sid == victim_sid else "VIA GROUP"
                    #via = all_victim_sids[trustee_sid]
                    #print(f"[{src}] {args.username} -> {target_name} ({obj_type})")
                    #print("Rights: ReadGMSAPassword")
                    #print(f"Mask: {hex(mask)}")
                    #print(f"Via: {via}")
                    #print("-" * 20)
                    #found = True
                    #ace_found = True
                            #if obj_type == "gmsa" and trustee_sid in all_victim_sids:
                            #print(f"[DEBUG GMSA] {target_name} has ACE with GUID: {obj_guid}, Mask: {hex(mask)}, Trustee in our list: {trustee_sid in all_victim_sids}")
                            #print(f"[DEBUG GMSA] Found ACE on {target_name}:")
                            #print(f"  Via: {all_victim_sids[trustee_sid]}")
                            #print(f"  ACE Type: {ace['AceType']}")
                            #print(f"  GUID Found: {obj_guid}")
                            #print(f"  GUID Expected: {GMSA_PASSWORD_GUID}")
                            #print(f"  Match: {obj_guid == GMSA_PASSWORD_GUID}")
                            #print(f"  Mask: {hex(mask)}")
                            #print(f"  Flags: {hex(ace['Ace']['Flags'])}")
                            #print()
                    #if not ace_found and ace['AceType'] == ACCESS_ALLOWED_ACE.ACE_TYPE:
                        #if mask & CONTROL_ACCESS:
                            #src = "DIRECT" if trustee_sid == victim_sid else "VIA GROUP"
                            #via = all_victim_sids[trustee_sid]
                            #print(f"[{src}] {args.username} -> {target_name} ({obj_type})")
                            #print("Rights: ReadGMSAPassword")
                            #print(f"Mask: {hex(mask)}")
                            #print(f"Via: {via}")
                            #print("-" * 20)
                            #found = True
                            #ace_found = True
                    #except Exception:
                        #pass
                    #except Exception as e:
                        #if obj_type == "gmsa":
                            #print(f"[DEBUG] Exception parsing GMSA GUID: {e}")
                        #print(f"[DEBUG] Exception in GMSA check: {e}")
                        #pass
# GMSA end          

            # GMSA
            #if ace['AceType'] in [ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE, ACCESS_ALLOWED_ACE.ACE_TYPE]:
                #if ace['Ace']['Flags'] & ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT:
                    #try:
                #is_gmsa = False
                #if ace['AceType'] == ACCESS_ALLOWED_ACE.ACE_TYPE:
                    #if ace['Ace']['Flags'] & ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT:
                        #try:
                            #obj_guid = UUID(bytes_le=ace['Ace']['ObjectType'])
                            #if obj_guid == GMSA_PASSWORD_GUID:
                                #is_gmsa = True
                        #except:
                            #pass
                #if is_gmsa:
                    #src = "DIRECT" if trustee_sid == victim_sid else "VIA GROUP"
                    #via = all_victim_sids[trustee_sid]
                    #print(f"[{src}] {args.username} -> {target_name} ({obj_type})")
                    #print("Rights: ReadGMSAPassword")
                    #print(f"Mask: {hex(mask)}")
                    #print(f"Via: {via}")
                    #print("-" * 20)
                    #found = True
                    #ace_found = True
                    #except Exception:
                        #pass
            # GMSA end
            # Addself detection end
            #forcechangepassword detection end
            # AL EXTENDED RIGTS
            #if ace['AceType'] == ACCESS_ALLOWED_ACE.ACE_TYPE:
                #if mask & 0x00000100:
                    #src = "DIRECT" if trustee_sid == victim_sid else "VIA GROUP"
                    #via = all_victim_sids[trustee_sid]

                    #print(f"[{src}] {args.username} -> {target_name} ({obj_type})")
                    #print(" Rights: ALL EXTENDED RIGHTS (ControlAccess)")
                    #print(f" Mask: {hex(mask)}")
                    #print(f" Via: {via}")
                    #print("-" * 20)

                    #found = True
                    #continue
            #if ace['AceType'] == 
            if not ace_found:
                rights = decode_mask(mask)
                if rights:
                    src = "DIRECT" if trustee_sid == victim_sid else "VIA GROUP"
                    via = all_victim_sids[trustee_sid]

                    print(f"[{src}] {args.username} -> {target_name} ({obj_type})")
                    print(f" Rights: {', '.join(rights)}")
                    print(f" Mask: {hex(mask)}")
                    print(f" Via: {via}")
                    print("-" * 20)
                    found = True
                #except Exception:
                    #continue
        #except Exception:
            #continue
    if not found:
        print(f"[-] No interesting ACL found")
                    #if (mask & GENERIC_ALL) or (mask & FULL_CONTROL_AD):
                        #print(f"Victim ({args.username}) has GENERIC_ALL on: {target_name}")
                        #print(f"Access Mask: {hex(mask)}")
                        #found_any = True
            #except:
                #continue
    #if not found_any:
        #print('nothing')
if __name__ == "__main__":
    main()
