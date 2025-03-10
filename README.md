HyperVeil is a sophisticated System Management Mode (SMM) framework that demonstrates how hardware-level memory access can be implemented securely. It includes:

UEFI SMM module - Core SMM handler implementing secure memory operations
Windows kernel driver - Communication layer with advanced anti-detection
User-mode control application - Graphical and CLI interface for operation
Security hardening components - Multiple protection layers and crypto verification
Project Structure

HyperVeil/
├── firmware/                   # SMM and UEFI components
│   ├── SmmHandler/             # SMM module implementation
│   ├── UefiApplication/        # UEFI installer
│   └── SecureBoot/             # Secure Boot key management
├── kernel/                     # Windows kernel driver
│   ├── Communication/          # SMM communication
│   ├── Memory/                 # Memory management and hiding
│   ├── Protection/             # Anti-detection techniques
│   └── Driver/                 # Core driver implementation
├── usermode/                   # User-mode application
│   ├── CLI/                    # Command-line interface
│   ├── GUI/                    # Graphical interface
│   └── DriverControl/          # Driver communication
├── common/                     # Shared components
│   ├── Crypto/                 # Cryptographic utilities
│   ├── Protocol/               # Communication protocol
│   └── Hardware/               # Hardware abstraction
├── build/                      # Build system
│   ├── edk2/                   # UEFI build configuration
│   ├── wdk/                    # Windows driver build
│   └── msbuild/                # User-mode build
└── doc/                        # Documentation