# FortiGate Automation Tool

This project automates the configuration of a **Remote Desktop VPN setup** on a FortiGate firewall using the FortiGate API.

It reduces manual configuration by automatically creating required objects and policies if they do not already exist.

---

## 🚀 Features

The tool performs the following automation tasks:

1. **IP Pool Management**
   - Creates the VPN client IP pool if it does not already exist.

2. **Address Group Setup**
   - Creates destination address groups when missing.

3. **User Group Creation**
   - Automatically creates the XAUTH user group.

4. **Firewall Policy Configuration**
   - Adds required Phase 2 VPN policies automatically.

5. **Rollback Functionality**
   - Automatically restores the previous state if deployment fails
   - Deletes all successfully created objects in reverse order
   - Prevents partial or broken VPN configurations after errors
---

## 🔐 Authentication

This tool uses a **FortiGate API token** for authentication.

For security, the API token is **not stored in plaintext**.  
Instead, it is stored in **Windows Credential Manager**.

---

## 💾 Storing the API Token (Windows)

Run the following command in **Command Prompt**:

```cmd
cmdkey /generic:FGT_API /user:anything /pass:YOUR_API_TOKEN
