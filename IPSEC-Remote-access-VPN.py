#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, messagebox
import requests, urllib3, ipaddress, os, time

urllib3.disable_warnings()

CRED_NAME = "FGT_API"
created_objects = []
stop_requested = False

# =============================
# AUTH
# =============================
def get_api_token():
    try:
        import win32cred
        cred = win32cred.CredRead(CRED_NAME, win32cred.CRED_TYPE_GENERIC)
        blob = cred["CredentialBlob"]
        return blob.decode("utf-16") if isinstance(blob, bytes) else blob
    except:
        return os.getenv("API_TOKEN")


def get_headers():
    token = get_api_token()
    if not token:
        raise Exception("Missing API token")
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

# =============================
# LOG
# =============================
def log(msg):
    log_box.insert(tk.END, msg + "\n")
    log_box.see(tk.END)
    root.update_idletasks()

# =============================
# SAFE CHECK (FIXED)
# =============================
def object_exists(url, headers, name):
    r = requests.get(
        url,
        headers=headers,
        params={"vdom": "root", "filter": f'name=="{name}"'},
        verify=False
    )
    try:
        data = r.json()
        return r.status_code == 200 and bool(data.get("results"))
    except:
        return False


# =============================
# SAFE CREATE
# =============================
def safe_create(url, headers, payload):
    name = payload.get("name")

    if object_exists(url, headers, name):
        log(f"[SKIP] {name} exists")
        return

    r = requests.post(
        url,
        headers=headers,
        json=payload,
        params={"vdom": "root"},
        verify=False
    )

    try:
        j = r.json()
    except:
        j = {}

    if r.status_code in [200, 201] and j.get("status") != "error":
        log(f"[OK] {name}")
        created_objects.append((url, name))
        return

    log(f"[FAIL] {name} -> {r.status_code}: {r.text}")
    raise Exception(name)


# =============================
# VALIDATION
# =============================
def valid_cidr(c):
    try:
        ipaddress.ip_network(c, strict=False)
        return True
    except:
        return False


def cidr_to_netmask(cidr):
    net = ipaddress.ip_network(cidr, strict=False)
    return str(net.network_address), str(net.netmask)


# =============================
# POLLING
# =============================
def wait_for_addrgrp_ready(base, headers, name, timeout=20):
    url = f"{base}/firewall/addrgrp"

    start = time.time()
    while time.time() - start < timeout:
        r = requests.get(
            url,
            headers=headers,
            params={"vdom": "root", "filter": f'name=="{name}"'},
            verify=False
        )

        try:
            j = r.json()
            if j.get("results"):
                return True
        except:
            pass

        time.sleep(1)

    return False
# =============================
# ROLLBACK
# =============================
def rollback(headers):
    log("⚠ Rolling back...")

    for url, name in reversed(created_objects):
        try:
            requests.delete(
                f"{url}/{name}",
                headers=headers,
                params={"vdom": "root"},
                verify=False
            )
        except:
            pass

    log("Rollback complete")


# =============================
# EXIT
# =============================
def exit_app(event=None):
    global stop_requested
    stop_requested = True
    root.destroy()

def wait_for_object(url, headers, name, timeout=20):
    start = time.time()

    while time.time() - start < timeout:
        try:
            r = requests.get(
                url,
                headers=headers,
                params={"vdom": "root", "filter": f'name=="{name}"'},
                verify=False
            )

            data = r.json()

            if r.status_code == 200 and data.get("results"):
                return True

        except:
            pass

        time.sleep(1)

    return False
# =============================
# DEPLOY
# =============================
def deploy():
    created_objects.clear()
    log_box.delete(1.0, tk.END)

    headers = get_headers()
    log("🔐 Using API token")

    data = {k: v.get().strip() for k, v in entries.items()}
    base = f"https://{data['FortiGate IP']}/api/v2/cmdb"

    addrgrp_name = data["Address Group"] + "_addrgrp"
    usergrp_name = data["Auth User Group"] + "_vpngrp"
    pool_name = f"{data['Tunnel Name']}_POOL"

    subnet_objects = []

    # -----------------------------
    # SUBNET COLLECTION
    # -----------------------------
    subnets = []
    for n, s in subnet_entries:
        if n.get() and s.get():
            if not valid_cidr(s.get()):
                messagebox.showerror("Error", f"Invalid subnet: {s.get()}")
                return
            subnets.append({"name": n.get(), "subnet": s.get()})

    try:
        # =============================
        # IP POOL
        # =============================
        safe_create(f"{base}/firewall/ippool", headers, {
            "name": pool_name,
            "type": "overload",
            "startip": data["IP Pool Start"],
            "endip": data["IP Pool End"]
        })

        # =============================
        # ADDRESS OBJECTS
        # =============================
        members = []

        for s in subnets:
            addr_name = f"{s['name']}_host"
            ip, mask = cidr_to_netmask(s["subnet"])

            safe_create(f"{base}/firewall/address", headers, {
                "name": addr_name,
                "type": "ipmask",
                "subnet": f"{ip} {mask}"
            })

            members.append({"name": addr_name})
            subnet_objects.append({"name": addr_name})

        # =============================
        # ADDRESS GROUP
        # =============================
        safe_create(f"{base}/firewall/addrgrp", headers, {
            "name": addrgrp_name,
            "member": members
        })

        # =============================
        # USER GROUP
        # =============================
        safe_create(f"{base}/user/group", headers, {
            "name": usergrp_name,
            "type": "firewall",
            "member": []
        })
        # =============================
        # 🔥 VPN DEPENDENCY SYNC CHECK
        # =============================
        log("⏳ Waiting for FortiGate VPN dependencies sync...")

        if not wait_for_addrgrp_ready(base, headers, addrgrp_name):
            rollback(headers)
            raise Exception(f"Address group not ready: {addrgrp_name}")

        if not wait_for_object(f"{base}/user/group", headers, usergrp_name):
            rollback(headers)
            raise Exception(f"User group not ready: {usergrp_name}")

        # =============================
        # PHASE1
        # =============================
        safe_create(f"{base}/vpn.ipsec/phase1-interface", headers, {
            "name": data["Tunnel Name"],
            "type": "dynamic",
            "interface": data["Interface"],
            "ike-version": 1,
            "mode": "aggressive",
            "peertype": "one",
            "peerid": data["Tunnel Name"],
            "net-device": "disable",
            "mode-cfg": "enable",
            "proposal": ["aes256-sha256", "aes128-sha1"],
            "dhgrp": 5,
            "xauthtype": "auto",
            "authusrgrp": usergrp_name,
            "ipv4-start-ip": data["IP Pool Start"],
            "ipv4-end-ip": data["IP Pool End"],
            "split-tunneling": "enable",
            "ipv4-split-include": addrgrp_name,
            "dns-mode": "auto",
            "psksecret": data["PSK"]
        })

        # =============================
        # PHASE2
        # =============================
        safe_create(f"{base}/vpn.ipsec/phase2-interface", headers, {
            "name": data["Tunnel Name"],
            "phase1name": data["Tunnel Name"],
            "proposal": ["aes256-sha256", "aes128-sha1"],
            "dhgrp": 5,
            "src-subnet": "0.0.0.0 0.0.0.0",
            "dst-subnet": "0.0.0.0 0.0.0.0"
        })

        # =============================
        # POLICY
        # =============================
        safe_create(f"{base}/firewall/policy", headers, {
            "name": f"{data['Tunnel Name']}_POLICY",
            "srcintf": [{"name": data["Tunnel Name"]}],
            "srcaddr": [{"name": "all"}],
            "dstintf": [{"name": data["LAN Interface"]}],
            "dstaddr": [{"name": addrgrp_name}],
            "action": "accept",
            "schedule": "always",
            "service": [{"name": "ALL"}],
            "nat": "enable"
        })
        log("✅ VPN FULLY CREATED SUCCESSFULLY")

    except Exception as e:
        rollback(headers)
        messagebox.showerror("ERROR", str(e))


# =============================
# GUI
# =============================
root = tk.Tk()
root.title("FortiGate Remote Access VPN Builder")
root.geometry("900x800")

frame = ttk.Frame(root)
frame.pack(fill="both", expand=True)

entries = {}

def field(name):
    f = ttk.Frame(frame)
    f.pack(fill="x")
    ttk.Label(f, text=name, width=22).pack(side="left")
    e = ttk.Entry(f)
    e.pack(fill="x", expand=True)
    entries[name] = e

for f in [
    "FortiGate IP",
    "Tunnel Name",
    "Interface",
    "LAN Interface",
    "PSK",
    "IP Pool Start",
    "IP Pool End",
    "Address Group",
    "Auth User Group"
]:
    field(f)

# -----------------------------
# SUBNET UI
# -----------------------------
subnet_entries = []
subnet_container = ttk.Frame(frame)
subnet_container.pack(fill="x", pady=5)

def add_subnet():
    f = ttk.Frame(subnet_container)
    f.pack(fill="x", pady=2)

    n = ttk.Entry(f, width=20)
    n.pack(side="left", padx=5)

    s = ttk.Entry(f, width=25)
    s.pack(side="left", padx=5)

    subnet_entries.append((n, s))

ttk.Button(frame, text="+ Subnet", command=add_subnet).pack()
add_subnet()

# -----------------------------
# BUTTONS
# -----------------------------
button_frame = ttk.Frame(frame)
button_frame.pack(fill="x", pady=10)

ttk.Button(button_frame, text="Deploy VPN", command=deploy).pack(side="left", padx=5)
ttk.Button(button_frame, text="Exit", command=exit_app).pack(side="right", padx=5)

# -----------------------------
# LOG
# -----------------------------
log_box = tk.Text(frame, height=15)
log_box.pack(fill="both", expand=True)

root.bind_all("<Escape>", exit_app)
root.bind_all("<Control-q>", exit_app)

root.mainloop()