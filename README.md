
# FIDO2 Yubikey Adminmanagement and Automated Registration for Entra ID - GUI Solution 

This tool allows you to manage fido2 security keys for the typical administration day - setting pins, resetting pins, resetting keys all in one GUI.
Additionally this tool also streamlines the process of registering FIDO2 security keys in **Microsoft Entra ID** by leveraging the FIDO2 Provisioning Graph API also in GUI. It supports singular user registrations and bulk enrollment with features like setting random PINs, managing keys, and logging results, through a user-friendly graphical interface.

## Features

- **Fido-Key Management**: Reset a Key, set a PIN, reset the PIN
- **Entra ID Integration**: Fully supports the FIDO2 Provisioning Graph API for seamless key registration.
- **Random PINs**: Generate random 6-digit custom PINs for FIDO2 keys.
- **Custom PINs**: A custom Pin can be set in the first line of the script.
- **Forced PIN Change**: Option to enforce PIN change after provisioning.
- **Clipboard Integration**: Automatically copies generated PINs to the clipboard for quick use.
- **Error Handling**: Provides clear prompts for errors and guides the user to resolve them.
- **Detailed Logging**: Logs all operations in a `.log` file for easy reference. 

## Prerequisites

### Required Hardware
- Compatible **FIDO2.1 key**:
  - Keys with FIDO2.1 Final firmware are required for setting and forcing PIN changes.
  - Serial number retrieval is supported only with the **PIN+ series** keys.

### Required Software
- **PowerShell**: Version 5.1 or later.
- **Modules**: 
  - `Microsoft.Graph`   (The script will automatically install these modules if not already present.)
  - `DSInternals.PassKeys` (The script will automatically install these modules if not already present.)

### Required Files
Ensure the following files are included in the archive:
- `libfido2-ui.exe`: Dependency of `fido2-manage.exe`.
- `fido2-cred2.exe`: Tool to create credentials directly on FIDO keys, compiled for NFC support to bypass Windows Hello.
- `ykman.exe`: Yubico's own Yubikey Management CLI Software.

### Input File
A CSV file containing user information. The file must include a column named `UPN` (User Principal Name).

### Permissions
- Run the script as **Administrator** (required due to Windows FIDO2 Native API limitations, script asks for admin on its own).
- The Entra account used must have the following **Graph API permissions**:
  - `UserAuthenticationMethod.ReadWrite.All`

### Additional Notes
If your Entra account is FIDO2/Passkey-protected, follow these steps:
1. Log in to an application like Microsoft Teams (even if unlicensed).
2. Choose the option **"Sign in to all your apps"**.
3. This will add your credentials to the session, allowing you to select the logged-in account when running the script.

## Using the Tool

1. **Run the Script**:
   Execute `EnrollFIDO2_fido2-cred.ps1` in PowerShell. Ensure the **execution policy** allows script execution. You can enable this by running:
   ```powershell
   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
   ```
   A graphical interface will appear.
   If you modify the script e.g. by modifying the PIN, you will need to use `Bypass` instead of `RemoteSigned`

### Key Management

1. **Change PIN**
   Enter old PIN and new PIN twice to change the current set PIN on key.
   Checks for PIN already set or both entries of new PIN must be the same.

2. **Set PIN**
   Sets a new PIN on Key if none is set yet. Just enter the new PIN twice.

3. **Reset Key**
   Resets the whole Yubikey and deletes stored PIN.
   Because of ykman restrictions, Button must be pressed within 5 Seconds of inserting the Yubikey.

### Key Enrollment

1. **Configure Tenant ID**:
   Enter your **Tenant ID** (e.g., `tenantname.onmicrosoft.com`). The tool will auto-detect the Tenant ID if available in the registry.

2. **Select the Input File or enter singular User UPN**:
   Click "Select File" and choose a valid CSV file containing user UPNs. (it defaults to `users.csv` in the script's own directory) 
   (we've also attached a small script to read out UPNs in correct format to a csv for AD)
   Alternatively if a singular User UPN is entered, it registers on behalf of the entered singular user.

3. **Set PIN Options**:
   - **Random PIN**: Generates a random 6-digit PIN for each key.
   - **Copy PIN to Clipboard**: Copies the generated PIN to the clipboard.
   - **Force PIN Change**: Enforces PIN change on the key.

4. **Set Log File Path**:
   Specify where the log file should be saved.

5. **Register Keys**:
   Click "Proceed" to start the registration process. The tool will:
   - Read the FIDO key serial number.
   - Optionally set a random PIN, otherwise `1234` will be set (or a previously chosen custom PIN).
   - Directly create the credential on the FIDO key for each user, bypassing the Windows Hello Interface
     - For fastest results, use an NFC reader as user presence is resolved by putting the FIDO key on the NFC reader, therefore no need to touch the touch area of the key.
   - Register the FIDO key for each user via the Graph API.
   - Log the results.
   - Show the upcoming user before whilst waiting for confirmation.
   - Logoff Graph Session after Enrollment is finished.

## Sample Log File

Here is an example of the log file content (formatted as CSV but saved with a `.log` extension to differentiate it from the user list file):

```plaintext
Date: 2024-11-28 12:34:56
------------------------------------------------------------
UPN, Serial Number, PIN, Forced PIN Change
john.doe@domain.com, 1234567890, 789012, Yes
jane.smith@domain.com, 0987654321, 456789, No
------------------------------------------------------------
```

Handle this log file carefully, as it contains sensitive information such as PINs. Please note that this will contain only successfully provisioned account information, not errors or failures. 

### ⚡ `EnrollFIDO2_fido2-cred.ps1`
- **Uses** the external `fido2-cred` tool instead of the Windows API
- **Writes credentials directly** to the key via command-line
- **Requires only a touch or NFC tap** on the key—**no PIN dialog**
- Much **faster and more efficient** for mass provisioning scenarios



## Troubleshooting

- **No Serial Number Detected**: Ensure the FIDO key is connected properly and try again. Only PIN+ series keys support serial number retrieval.
- **Error Connecting to Graph API**: Verify the Tenant ID and ensure the necessary permissions are assigned.
- **Tool Doesn't Launch**: Confirm required modules are installed and run the script with appropriate permissions.
- **Tool fails setting the PIN**: On PIN+ Octo Devices, due to the mininum PIN length of 8 digits, the automatic PIN Generation will fail. you can change the non random PIN in the script by changing the sample PIN in the first line to any PIN of your liking, beware of the other [PIN+ rules](https://www.token2.swiss/site/page/token2-fido2-pin-see-the-pin-complexity-in-action).

## Contact

This Project was done by Roman and Pierre from Germany. We're just two Sysadmins finding ways to get managing and enrolling SecurityKeys, especially Yubikeys under one banner.
Out thanks goes out to token2 as this idea was forked off of token2's own Enrollment Idea in their own way (https://github.com/token2/fido2_bulkenroll_entraid)
In hopes this may find someone in the same situation as us and thinking "Man, we cant be alone with our Issue on the whole world", as we did.

---

This project partially licensed under the [MIT License](LICENSE), except the **read_serial_t2.exe** utility.

This project uses code sections from the Powershell version of [DSInternals.PassKeys](https://github.com/MichaelGrafnetter/webauthn-interop), under the MIT License for interactions with Microsoft Graph.
