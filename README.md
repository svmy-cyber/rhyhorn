# Windows Sandbox Hardening Script

A PowerShell-based security hardening tool for Windows systems that implements multiple layers of security controls through a structured, sequence-based approach.

## Editions

Two self-contained editions ship side by side (each as an EXE and a PowerShell script). Both aim for a browse-only, attack-surface-minimised sandbox, but take different approaches:

| Edition | File | Approach | Highlights |
| --- | --- | --- | --- |
| **Classic** | `HardenSandbox.ps1` | Lockdown by *removal & restriction* | Black-hole routing for RFC1918, IPv6/NetBIOS off, Software Restriction Policies with SHA-256 allow-list, restricted PS policy, cmd/Task Manager/registry tools disabled |
| **Fable** | `harden_fable.ps1` | Lockdown by *containment* | Firewall outbound default-deny + minimal allow-list, malware-filtering DNS (Quad9), Defender ASR + DEP/SEHOP/ASLR/CFG, LOLBin neutering via IFEO, PowerShell Constrained Language Mode |

The **Classic** edition is documented in detail below. The **Fable** edition is idempotent and self-documenting — see the header comment in [`harden_fable.ps1`](harden_fable.ps1) for the full rationale and per-section trade-offs.

## Features

### Network Security
- Blocks access to private networks (RFC1918) using black hole routing
- Disables IPv6 components
- Disables NetBIOS over TCP/IP
- Disables Network Discovery

### System Hardening
- Restricts Windows Script Host
- Enforces restricted PowerShell execution policy
- Disables Remote Desktop connections
- Implements Software Restriction Policies (SRP) for process control
- Disables command prompt access
- Restricts access to Registry Tools and Task Manager

### Browser Security (Microsoft Edge)
- Enables SmartScreen protection
- Disables JavaScript JIT compilation
- Restricts download capabilities
- Blocks extension installations
- Disables autofill features
- Enforces TLS 1.2
- Restricts various browser permissions (geolocation, notifications, etc.)

## Requirements

- Windows 10 or Windows Server 2016 and above
- PowerShell 5.1 or higher
- Administrative privileges
- Microsoft Edge browser (for browser hardening features)

## Installation

1. Download the `Windows-Hardening.ps1` script
2. Verify the script's digital signature (if provided)
3. Place the script in your preferred location

## Usage

```powershell
# Run as Administrator
.\Windows-Hardening.ps1
```

**Important**: Always test this script in a controlled environment before deploying to production systems.

## Script Components

### Classes
- `SecurityFeature`: Defines security settings and their properties
- `NetworkBlock`: Defines network blocking rules
- `HardeningManager`: Main class that manages the hardening process

### Sequence Stages
1. Network Controls (Stage 1)
2. System Hardening (Stage 2)
3. Browser Security (Stage 3)
4. Advanced Restrictions (Stage 4)
5. Final Lockdown (Stage 5)

## Logging

The script generates detailed logs including:
- Applied security features
- Network blocks
- Allowed processes
- Errors and warnings
- Summary statistics

Logs are saved to: `%USERPROFILE%\Desktop\HardeningResults_[timestamp].log`

## Verification

The script includes comprehensive verification:
- Registry setting validation
- Network route verification
- Process restriction validation
- Browser configuration checks

## Customization

### Adding Network Blocks
```powershell
$this.NetworkBlocks.Add([NetworkBlock]::new(
    "192.168.1.0",    # Subnet
    "255.255.255.0",  # Mask
    "192.168.1.1",    # Test IP
    "Description"     # Description
))
```

### Adding Allowed Processes
```powershell
$this.AllowedProcesses.Add("process.exe")
```

### Adding Security Features
```powershell
$this.AddFeature(
    "Feature Name",
    "Registry Key Path",
    "Value Name",
    $value,
    "Value Type",
    "Category",
    $sequenceOrder
)
```

## Security Considerations

- The script implements restrictive controls that may impact system usability
- Some features (like disabling Task Manager) could make troubleshooting difficult
- Network blocks affect internal network communication
- Process restrictions may impact application functionality
- Always maintain a way to reverse these changes in case of issues

## Troubleshooting

### Common Issues
1. **Network Connectivity Issues**
   - Check the network blocks in the log file
   - Verify route configurations using `Get-NetRoute`

2. **Process Restrictions**
   - Review Software Restriction Policies
   - Check the allowed processes list

3. **Browser Issues**
   - Verify Edge policy settings in Registry
   - Check Edge browser version compatibility

### Recovery
1. Keep a backup of critical system settings
2. Document any customizations made to the script
3. Maintain a separate admin account that isn't affected by restrictions

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed changes
4. Include test results from a controlled environment

## License

MIT License - Feel free to use and modify as needed, but please include attribution.

## Disclaimer

This script implements significant security controls that may impact system functionality. Use at your own risk and always test thoroughly before deployment.