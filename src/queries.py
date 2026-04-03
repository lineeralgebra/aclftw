import time
import ssl
import os
from ldap3 import Server, ALL, Connection, NTLM, SUBTREE, Tls, MODIFY_ADD, MODIFY_REPLACE, SASL, KERBEROS
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID, ACE, ACCESS_ALLOWED_ACE, ACCESS_MASK
from rich import print
import readline
import rlcompleter
import atexit
import heapq
import shlex

from src.structs import Session, Queue, DecisionNode, TreeNode, HistoryNode, SinglyLinkedList, SessionManager, BSTNode, UserCacheBST
from src.utils import sid_to_string, resolve_member_name, resolve_sid
def batch_lookup(conn, base_dn):

    priority_map = {"administrator": 1, "krbtgt": 1, "guest": 3}

    users = ["osman", "mark", "Administrator", "guest", "irem", "krbtgt"]
    pq = []

    for u in users:
        priority = priority_map.get(u.lower(), 2)
        heapq.heappush(pq, (priority, u))
    print(f"{len(pq)} users queued with priority logic")

    while pq:
        priority, username = heapq.heappop(pq)
        print(f"[+] [{priority}] Checking {username}...")
        conn.search(base_dn, f"(sAMAccountName={username})", attributes=["cn"])

        if conn.entries:
            print(f"[bold green]Found: {username}[/bold green]")
        else:
            print(f"[bold red]Not Found: {username}[/bold red]")


    # enqueu users
    queue = Queue()
    for u in users:
        queue.enqueue(u)
    print(f"[+] {queue.size()} users queued")

    while not queue.is_empty():
        username = queue.dequeue()
        print(f"[+] Checking {username}")
        conn.search(base_dn, f"(sAMAccountName={username})", attributes=["cn"])

        if conn.entries:
            print(f"[+] {username} exist")
        else:
            print(f"[-] {username} not found")

def build_category_tree(conn, base_dn):
    root = TreeNode("Objects")
    users_node = TreeNode("Users")
    computers_node = TreeNode("Computers")

    root.children.append(users_node)
    root.children.append(computers_node)

    # query users
    conn.search(base_dn, "(objectClass=user)", attributes=['sAMAccountName'], size_limit=1000)

    for entry in conn.entries:
        users_node.children.append(TreeNode(str(entry.sAMAccountName)))
    # query compouters
    conn.search(base_dn, "(objectClass=computer)", attributes=['sAMAccountName'], size_limit=1000)

    for entry in conn.entries:
        computers_node.children.append(TreeNode(str(entry.sAMAccountName)))

    return root

def print_categories(root):

    for category in root.children:
        print(f"\n[bold cyan]{category.value}[/bold cyan]")

        for obj in category.children:
            print(f"- {obj.value}")



def list_groups_bfs(conn, base_dn):
    # fopr find al l groups
    conn.search(base_dn, "(objectClass=group)", attributes=["cn", "member"])

    groups = {}

    for entry in conn.entries:
        name = str(entry.cn)
        members = entry.member.values if "member" in entry else []
        groups[name] = members

    for group in groups:
        print(f"\n[bold cyan]{group}[/bold cyan]")
        queue = Queue()
        # enmque first level members
        for m in groups[group]:
            queue.enqueue(m)

        while not queue.is_empty():

            member = queue.dequeue()

            # resolve to friendly name (handles both DN and SID)
            cn = resolve_member_name(conn, base_dn, member)
            print(f"[bold yellow]|_{cn}[/bold yellow]")

            if cn in groups:
                for submember in groups[cn]:
                    queue.enqueue(submember)

def list_users(conn, base_dn, user_cache):
    conn.search(base_dn, "(&(objectClass=User)(!(objectClass=computer)))", attributes=["sAMAccountName", "description"]) # we can add more tho

    print("\n[bold cyan]Users[/bold cyan]")

    with open("usernames.txt", "w") as outfile:


        for entry in conn.entries:

            user = str(entry.sAMAccountName)

            user_cache.insert(user, str(entry))

            desc = ""

            if "description" in entry:
                desc = str(entry.description)
            print(f"[bold yellow]{user} - {desc}[/bold yellow]")

            outfile.write(user + "\n")
    print(f"[+] {len(conn.entries)} usernames saved to usernames.txt")
def list_computers(conn, base_dn):
    conn.search(base_dn, "(objectClass=computer)", attributes=["sAMAccountName", "dNSHostname", "operatingSystem", "memberOf", "distinguishedName"]) # we can add more tho

    print("\n[bold cyan]Computers[/bold cyan]")

    for entry in conn.entries:

        comp = str(entry.sAMAccountName)
        dnshostname = str(entry.dNSHostname)
        operatingsystem = str(entry.operatingSystem)
        membersof = str(entry.memberOf)
        distinguishedNamee = str(entry.distinguishedName)
        print(f"[bold yellow]{comp} - {dnshostname} - {operatingsystem} - {distinguishedNamee}[/bold yellow]")
        if "Pre-Windows 2000" in membersof:
            if not "Domain Controllers" in distinguishedNamee:
                print(f"[bold red]{comp} has weakkness try pre2k for this computer[/bold red]")

def kerberoastable(conn, base_dn):
    conn.search(base_dn, "(&(objectClass=user)(!(objectClass=computer))(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))", attributes=["sAMAccountName", "servicePrincipalName"])
    print("\n[bold red]Kerberoastable Accounts[/bold red]")

    for entry in conn.entries:
        user = str(entry.sAMAccountName)

        spn = ""

        if "servicePrincipalName" in entry:
            spn = str(entry.servicePrincipalName)
        print(f"[bold red] {user} - {spn}[/bold red]")

def get_sid(conn, base_dn, username):
    """Retrieve and display the SID for a given user."""
    conn.search(base_dn, f"(sAMAccountName={username})", attributes=["objectSid", "sAMAccountName", "distinguishedName"])
    if not conn.entries:
        print(f"[bold red][-] User '{username}' not found[/bold red]")
        return
    entry = conn.entries[0]
    raw_sid = entry["objectSid"].raw_values[0]
    sid_str = sid_to_string(raw_sid)
    print(f"\n[bold cyan]SID for {username}[/bold cyan]")
    print(f"[bold yellow]  User : {entry.sAMAccountName}[/bold yellow]")
    print(f"[bold yellow]  DN   : {entry.distinguishedName}[/bold yellow]")
    print(f"[bold green]  SID  : {sid_str}[/bold green]")

def get_maq(conn, base_dn):
    conn.search(search_base=base_dn, search_filter="(objectClass=domain)", attributes=["ms-DS-MachineAccountQuota"])

    if not conn.entries:
        print(f"[bold red][-]Could not retrieve MAQ[/bold red]")
        return

    entry = conn.entries[0]
    if "ms-DS-MachineAccountQuota" in entry:
        maq = int(entry["ms-DS-MachineAccountQuota"].value)
        print(f"[bold cyan][+] Machine Account Quota (MAQ):[/bold cyan] [bold green]{maq}[/bold green]")
        if maq > 0:
            print("[bold yellow][!] Users can create machine accounts![/bold yellow]")
        else:
            print("[bold green][+] Machine account creation is restricted[/bold green]")
    else:
        print("[bold red][-] MAQ attribute not found[/bold red]")