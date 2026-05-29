<#
.SYNOPSIS
    SelfSignedCert-Manager-Final-Fixed.ps1
    GUI-Tool zum Erstellen, Exportieren, Auflisten und Löschen selbstsignierter Zertifikate.

.FIXES IN V4
    - Behebt: NTE_PROV_TYPE_NOT_DEF / "Der Anbietertyp ist nicht definiert"
      Ursache war die Kombination aus CNG-KSP "Microsoft Software Key Storage Provider" und KeySpec.
    - Verwendet jetzt Provider-Fallbacks:
        1. Microsoft Software Key Storage Provider ohne KeySpec
        2. Microsoft Enhanced RSA and AES Cryptographic Provider mit KeySpec KeyExchange
        3. Windows Default Provider ohne Providerangabe
    - Kein -IPAddress Parameter.
    - DNS/IP-SANs werden kompatibel über TextExtension gesetzt.
    - Zertifikatsliste per DataTable.
    - DPI-/RDP-/AVD-tauglicheres Layout.

.NOTES
    Für Cert:\LocalMachine\* und LocalMachine\Root PowerShell als Administrator starten.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\SelfSignedCert-Manager-Final-Fixed.ps1
#>
