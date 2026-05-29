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

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[System.Windows.Forms.Application]::EnableVisualStyles()

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-GuiLog {
    param(
        [System.Windows.Forms.TextBox]$TextBox,
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $TextBox.AppendText("[$timestamp] [$Level] $Message" + [Environment]::NewLine)
    $TextBox.SelectionStart = $TextBox.Text.Length
    $TextBox.ScrollToCaret()
}

function Get-SafeFileName {
    param([string]$Name)

    foreach ($char in [IO.Path]::GetInvalidFileNameChars()) {
        $Name = $Name.Replace($char, '_')
    }

    return $Name
}


function ConvertTo-X500EscapedValue {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    $v = $Value.Trim()
    $v = $v.Replace('\\', '\\\\')
    $v = $v.Replace(',', '\,')
    $v = $v.Replace('+', '\+')
    $v = $v.Replace('"', '\"')
    $v = $v.Replace('<', '\<')
    $v = $v.Replace('>', '\>')
    $v = $v.Replace(';', '\;')
    return $v
}

function New-X500Subject {
    param(
        [string]$CN,
        [string]$OU,
        [string]$O,
        [string]$L,
        [string]$ST,
        [string]$C,
        [string]$E
    )

    $parts = New-Object System.Collections.Generic.List[string]

    foreach ($entry in @(
        @{ Name = 'CN'; Value = $CN },
        @{ Name = 'OU'; Value = $OU },
        @{ Name = 'O';  Value = $O  },
        @{ Name = 'L';  Value = $L  },
        @{ Name = 'ST'; Value = $ST },
        @{ Name = 'C';  Value = $C  },
        @{ Name = 'E';  Value = $E  }
    )) {
        $escaped = ConvertTo-X500EscapedValue -Value $entry.Value
        if ($escaped) {
            [void]$parts.Add("$($entry.Name)=$escaped")
        }
    }

    return ($parts -join ', ')
}

function Convert-CerToPem {
    param(
        [Parameter(Mandatory)][string]$CerPath,
        [Parameter(Mandatory)][string]$PemPath
    )

    $bytes = [System.IO.File]::ReadAllBytes($CerPath)
    $base64 = [Convert]::ToBase64String($bytes, [Base64FormattingOptions]::InsertLineBreaks)

    $pem = @"
-----BEGIN CERTIFICATE-----
$base64
-----END CERTIFICATE-----
"@

    Set-Content -Path $PemPath -Value $pem -Encoding ascii -Force
}


function Export-PrivateKeyToPem {
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory)]
        [string]$KeyPath
    )

    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)

    if (-not $rsa) {
        throw 'Kein RSA Private Key im Zertifikat gefunden.'
    }

    try {
        $keyBytes = $rsa.ExportPkcs8PrivateKey()
    }
    catch {
        throw "Private Key konnte nicht exportiert werden. Ursache: $($_.Exception.Message)"
    }

    $base64 = [Convert]::ToBase64String($keyBytes, [Base64FormattingOptions]::InsertLineBreaks)

    $pem = @"
-----BEGIN PRIVATE KEY-----
$base64
-----END PRIVATE KEY-----
"@

    Set-Content -Path $KeyPath -Value $pem -Encoding ascii -Force
}

function New-Label {
    param(
        [string]$Text,
        [int]$X,
        [int]$Y,
        [int]$Width = 180,
        [int]$Height = 22
    )

    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    $label.Location = New-Object System.Drawing.Point($X, $Y)
    $label.Size = New-Object System.Drawing.Size($Width, $Height)
    return $label
}

function New-TextBox {
    param(
        [int]$X,
        [int]$Y,
        [int]$Width = 360,
        [string]$Text = ''
    )

    $tb = New-Object System.Windows.Forms.TextBox
    $tb.Location = New-Object System.Drawing.Point($X, $Y)
    $tb.Size = New-Object System.Drawing.Size($Width, 24)
    $tb.Text = $Text
    return $tb
}

function New-ComboBox {
    param(
        [int]$X,
        [int]$Y,
        [int]$Width = 180,
        [string[]]$Items,
        [string]$SelectedItem
    )

    $cb = New-Object System.Windows.Forms.ComboBox
    $cb.Location = New-Object System.Drawing.Point($X, $Y)
    $cb.Size = New-Object System.Drawing.Size($Width, 24)
    $cb.DropDownStyle = 'DropDownList'
    [void]$cb.Items.AddRange($Items)
    $cb.SelectedItem = $SelectedItem
    return $cb
}

function New-CheckBox {
    param(
        [string]$Text,
        [int]$X,
        [int]$Y,
        [int]$Width = 300,
        [bool]$Checked = $false
    )

    $cb = New-Object System.Windows.Forms.CheckBox
    $cb.Text = $Text
    $cb.Location = New-Object System.Drawing.Point($X, $Y)
    $cb.Size = New-Object System.Drawing.Size($Width, 24)
    $cb.Checked = $Checked
    return $cb
}

function Get-EkuText {
    param(
        [bool]$ServerAuth,
        [bool]$ClientAuth,
        [bool]$CodeSigning,
        [bool]$DocumentSigning
    )

    $eku = @()

    if ($ServerAuth)      { $eku += '1.3.6.1.5.5.7.3.1' }
    if ($ClientAuth)      { $eku += '1.3.6.1.5.5.7.3.2' }
    if ($CodeSigning)     { $eku += '1.3.6.1.5.5.7.3.3' }
    if ($DocumentSigning) { $eku += '1.3.6.1.4.1.311.10.3.12' }

    if ($eku.Count -eq 0) {
        $eku += '1.3.6.1.5.5.7.3.1'
    }

    return "2.5.29.37={text}$($eku -join ',')"
}

function Get-SanTextExtension {
    param(
        [string[]]$DnsNames,
        [string[]]$IpAddresses
    )

    $items = @()

    foreach ($dns in $DnsNames) {
        if (-not [string]::IsNullOrWhiteSpace($dns)) {
            $items += "dns=$dns"
        }
    }

    foreach ($ip in $IpAddresses) {
        if (-not [string]::IsNullOrWhiteSpace($ip)) {
            $items += "ipaddress=$ip"
        }
    }

    if ($items.Count -eq 0) {
        return $null
    }

    return "2.5.29.17={text}$($items -join '&')"
}

function Get-CertDataTable {
    param([string]$StorePath)

    $table = New-Object System.Data.DataTable
    [void]$table.Columns.Add('Store', [string])
    [void]$table.Columns.Add('Subject', [string])
    [void]$table.Columns.Add('FriendlyName', [string])
    [void]$table.Columns.Add('Thumbprint', [string])
    [void]$table.Columns.Add('NotBefore', [string])
    [void]$table.Columns.Add('NotAfter', [string])
    [void]$table.Columns.Add('DaysLeft', [int])
    [void]$table.Columns.Add('HasPrivateKey', [string])
    [void]$table.Columns.Add('Issuer', [string])
    [void]$table.Columns.Add('SAN', [string])

    if (-not (Test-Path $StorePath)) {
        return $table
    }

    $certs = Get-ChildItem -Path $StorePath -ErrorAction Stop

    foreach ($cert in $certs) {
        $san = ''

        try {
            $sanExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
            if ($sanExt) {
                $san = $sanExt.Format($false)
            }
        } catch {}

        $daysLeft = 0
        try {
            $daysLeft = [int][Math]::Floor(($cert.NotAfter - (Get-Date)).TotalDays)
        } catch {}

        $row = $table.NewRow()
        $row['Store'] = $StorePath
        $row['Subject'] = [string]$cert.Subject
        $row['FriendlyName'] = [string]$cert.FriendlyName
        $row['Thumbprint'] = [string]$cert.Thumbprint
        $row['NotBefore'] = $cert.NotBefore.ToString('yyyy-MM-dd HH:mm')
        $row['NotAfter'] = $cert.NotAfter.ToString('yyyy-MM-dd HH:mm')
        $row['DaysLeft'] = $daysLeft
        $row['HasPrivateKey'] = [string]$cert.HasPrivateKey
        $row['Issuer'] = [string]$cert.Issuer
        $row['SAN'] = [string]$san
        [void]$table.Rows.Add($row)
    }

    return $table
}

function New-CertificateWithFallback {
    param(
        [hashtable]$BaseParams,
        [System.Windows.Forms.TextBox]$LogBox
    )

    $attempts = @(
        @{
            Name = 'Microsoft Software Key Storage Provider ohne KeySpec'
            Add  = @{
                Provider = 'Microsoft Software Key Storage Provider'
            }
        },
        @{
            Name = 'Microsoft Enhanced RSA and AES Cryptographic Provider mit KeySpec KeyExchange'
            Add  = @{
                Provider = 'Microsoft Enhanced RSA and AES Cryptographic Provider'
                KeySpec  = 'KeyExchange'
            }
        },
        @{
            Name = 'Windows Default Provider ohne Providerangabe'
            Add  = @{}
        }
    )

    $lastError = $null

    foreach ($attempt in $attempts) {
        try {
            $params = @{}
            foreach ($key in $BaseParams.Keys) {
                $params[$key] = $BaseParams[$key]
            }

            foreach ($key in $attempt.Add.Keys) {
                $params[$key] = $attempt.Add[$key]
            }

            Write-GuiLog -TextBox $LogBox -Level 'INFO' -Message "Versuche Provider: $($attempt.Name)"
            $cert = New-SelfSignedCertificate @params -ErrorAction Stop
            Write-GuiLog -TextBox $LogBox -Level 'SUCCESS' -Message "Provider erfolgreich: $($attempt.Name)"
            return $cert
        }
        catch {
            $lastError = $_.Exception.Message
            Write-GuiLog -TextBox $LogBox -Level 'WARN' -Message "Provider fehlgeschlagen: $($attempt.Name) / $lastError"
        }
    }

    throw "Zertifikat konnte mit keinem Provider erstellt werden. Letzter Fehler: $lastError"
}

$isAdmin = Test-IsAdmin

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Self-Signed Certificate Manager'
$form.AutoScaleMode = 'Dpi'
$form.Size = New-Object System.Drawing.Size(1220, 1080)
$form.MinimumSize = New-Object System.Drawing.Size(1220, 1080)
$form.StartPosition = 'CenterScreen'
$form.BackColor = [System.Drawing.Color]::FromArgb(238,242,247)

$title = New-Object System.Windows.Forms.Label
$title.Text = 'Self-Signed Certificate Manager'
$title.Font = New-Object System.Drawing.Font('Segoe UI', 16, [System.Drawing.FontStyle]::Bold)
$title.Location = New-Object System.Drawing.Point(20, 12)
$title.Size = New-Object System.Drawing.Size(760, 34)
$title.ForeColor = [System.Drawing.Color]::FromArgb(20,54,96)
$form.Controls.Add($title)

$adminLabel = New-Object System.Windows.Forms.Label
$adminLabel.Location = New-Object System.Drawing.Point(22, 48)
$adminLabel.Size = New-Object System.Drawing.Size(1100, 22)
$adminLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9)
if ($isAdmin) {
    $adminLabel.Text = 'Status: PowerShell läuft als Administrator. LocalMachine-Store und Trusted Root LocalMachine sind verfügbar.'
    $adminLabel.ForeColor = [System.Drawing.Color]::DarkGreen
} else {
    $adminLabel.Text = 'Hinweis: Nicht als Administrator gestartet. LocalMachine-Store, Trusted Root LocalMachine und Löschen dort benötigen Adminrechte.'
    $adminLabel.ForeColor = [System.Drawing.Color]::DarkOrange
}
$form.Controls.Add($adminLabel)

$copyrightLabel = New-Object System.Windows.Forms.Label
$copyrightLabel.Text = '© 2026 Crowd'
$copyrightLabel.Location = New-Object System.Drawing.Point(935, 18)
$copyrightLabel.Size = New-Object System.Drawing.Size(240, 22)
$copyrightLabel.Anchor = 'Top,Right'
$copyrightLabel.TextAlign = 'MiddleRight'
$copyrightLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$copyrightLabel.ForeColor = [System.Drawing.Color]::FromArgb(20,54,96)
$form.Controls.Add($copyrightLabel)

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Location = New-Object System.Drawing.Point(20, 80)
$tabs.Size = New-Object System.Drawing.Size(1160, 735)
$tabs.Anchor = 'Top,Bottom,Left,Right'
$form.Controls.Add($tabs)

$tabCreate = New-Object System.Windows.Forms.TabPage
$tabCreate.Text = 'Zertifikat erstellen'
$tabCreate.BackColor = [System.Drawing.Color]::FromArgb(248,250,252)
$tabs.Controls.Add($tabCreate)

$tabManage = New-Object System.Windows.Forms.TabPage
$tabManage.Text = 'Zertifikate verwalten'
$tabManage.BackColor = [System.Drawing.Color]::FromArgb(248,250,252)
$tabs.Controls.Add($tabManage)

# Create Tab
$groupInput = New-Object System.Windows.Forms.GroupBox
$groupInput.Text = 'Zertifikatseinstellungen'
$groupInput.Location = New-Object System.Drawing.Point(15, 15)
$groupInput.Size = New-Object System.Drawing.Size(1110, 355)
$groupInput.Anchor = 'Top,Left,Right'
$groupInput.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$groupInput.BackColor = [System.Drawing.Color]::FromArgb(248,250,252)
$groupInput.ForeColor = [System.Drawing.Color]::FromArgb(20,54,96)
$tabCreate.Controls.Add($groupInput)

$groupInput.Controls.Add((New-Label 'Common Name / CN:' 20 32))
$txtCN = New-TextBox 250 30 790 'server.domain.local'
$txtCN.Anchor = 'Top,Left,Right'
$groupInput.Controls.Add($txtCN)

$groupInput.Controls.Add((New-Label 'DNS/IP SANs:' 20 67))
$txtDns = New-TextBox 250 65 790 'server.domain.local, server, localhost, 192.168.1.10'
$txtDns.Anchor = 'Top,Left,Right'
$groupInput.Controls.Add($txtDns)

$hintDns = New-Object System.Windows.Forms.Label
$hintDns.Text = 'Mehrere Einträge mit Komma trennen. DNS-Namen und IP-Adressen sind möglich. Der CN wird automatisch ergänzt.'
$hintDns.Location = New-Object System.Drawing.Point(250, 91)
$hintDns.Size = New-Object System.Drawing.Size(800, 20)
$hintDns.ForeColor = [System.Drawing.Color]::DimGray
$groupInput.Controls.Add($hintDns)

$groupInput.Controls.Add((New-Label 'Gültigkeit in Jahren:' 20 122))
$numYears = New-Object System.Windows.Forms.NumericUpDown
$numYears.Location = New-Object System.Drawing.Point(250, 120)
$numYears.Size = New-Object System.Drawing.Size(100, 24)
$numYears.Minimum = 1
$numYears.Maximum = 30
$numYears.Value = 3
$groupInput.Controls.Add($numYears)

$groupInput.Controls.Add((New-Label 'Key Length:' 390 122 100))
$cmbKeyLength = New-ComboBox 500 120 130 @('2048','3072','4096') '2048'
$groupInput.Controls.Add($cmbKeyLength)

$groupInput.Controls.Add((New-Label 'Hash Algorithmus:' 670 122 130))
$cmbHash = New-ComboBox 810 120 230 @('SHA256','SHA384','SHA512') 'SHA256'
$groupInput.Controls.Add($cmbHash)

$groupInput.Controls.Add((New-Label 'Ziel-Store:' 20 157))
$cmbStore = New-ComboBox 250 155 250 @('CurrentUser\My','LocalMachine\My') 'CurrentUser\My'
$groupInput.Controls.Add($cmbStore)

$groupInput.Controls.Add((New-Label 'Friendly Name:' 530 157 120))
$txtFriendly = New-TextBox 660 155 380 'SelfSigned Certificate'
$txtFriendly.Anchor = 'Top,Left,Right'
$groupInput.Controls.Add($txtFriendly)

$groupInput.Controls.Add((New-Label 'Provider-Modus:' 20 192))
$txtProvider = New-TextBox 250 190 790 'Auto-Fallback: Software KSP -> Enhanced RSA/AES CSP -> Windows Default'
$txtProvider.ReadOnly = $true
$txtProvider.BackColor = [System.Drawing.Color]::WhiteSmoke
$txtProvider.Anchor = 'Top,Left,Right'
$groupInput.Controls.Add($txtProvider)

$groupInput.Controls.Add((New-Label 'Organization Unit / OU:' 20 232))
$txtOU = New-TextBox 250 230 300 ''
$groupInput.Controls.Add($txtOU)

$groupInput.Controls.Add((New-Label 'Organization / O:' 580 232 130))
$txtO = New-TextBox 720 230 320 ''
$txtO.Anchor = 'Top,Left,Right'
$groupInput.Controls.Add($txtO)

$groupInput.Controls.Add((New-Label 'City / Locality / L:' 20 267))
$txtL = New-TextBox 250 265 300 ''
$groupInput.Controls.Add($txtL)

$groupInput.Controls.Add((New-Label 'State / Province / ST:' 580 267 150))
$txtST = New-TextBox 720 265 320 ''
$txtST.Anchor = 'Top,Left,Right'
$groupInput.Controls.Add($txtST)

$groupInput.Controls.Add((New-Label 'Country / C:' 20 302))
$txtC = New-TextBox 250 300 80 'DE'
$groupInput.Controls.Add($txtC)

$groupInput.Controls.Add((New-Label 'E-Mail / E:' 390 302 100))
$txtE = New-TextBox 500 300 540 ''
$txtE.Anchor = 'Top,Left,Right'
$groupInput.Controls.Add($txtE)

$groupEku = New-Object System.Windows.Forms.GroupBox
$groupEku.Text = 'Enhanced Key Usage'
$groupEku.Location = New-Object System.Drawing.Point(15, 380)
$groupEku.Size = New-Object System.Drawing.Size(1110, 80)
$groupEku.Anchor = 'Top,Left,Right'
$groupEku.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$groupEku.BackColor = [System.Drawing.Color]::FromArgb(248,250,252)
$groupEku.ForeColor = [System.Drawing.Color]::FromArgb(20,54,96)
$tabCreate.Controls.Add($groupEku)

$chkServerAuth = New-CheckBox 'Server Authentication' 20 32 190 $true
$chkClientAuth = New-CheckBox 'Client Authentication' 250 32 190 $false
$chkCodeSigning = New-CheckBox 'Code Signing' 480 32 150 $false
$chkDocumentSigning = New-CheckBox 'Document Signing' 670 32 170 $false
$groupEku.Controls.Add($chkServerAuth)
$groupEku.Controls.Add($chkClientAuth)
$groupEku.Controls.Add($chkCodeSigning)
$groupEku.Controls.Add($chkDocumentSigning)

$groupExport = New-Object System.Windows.Forms.GroupBox
$groupExport.Text = 'Export'
$groupExport.Location = New-Object System.Drawing.Point(15, 470)
$groupExport.Size = New-Object System.Drawing.Size(1110, 150)
$groupExport.Anchor = 'Top,Left,Right'
$groupExport.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$groupExport.BackColor = [System.Drawing.Color]::FromArgb(248,250,252)
$groupExport.ForeColor = [System.Drawing.Color]::FromArgb(20,54,96)
$tabCreate.Controls.Add($groupExport)

$groupExport.Controls.Add((New-Label 'Export-Ordner:' 20 32))
$txtExportPath = New-TextBox 250 30 680 'C:\install\Zertifikate'
$txtExportPath.Anchor = 'Top,Left,Right'
$groupExport.Controls.Add($txtExportPath)

$btnBrowse = New-Object System.Windows.Forms.Button
$btnBrowse.Text = 'Durchsuchen'
$btnBrowse.Location = New-Object System.Drawing.Point(950, 28)
$btnBrowse.Size = New-Object System.Drawing.Size(130, 28)
$btnBrowse.Anchor = 'Top,Right'
$groupExport.Controls.Add($btnBrowse)

$chkExportPfx = New-CheckBox 'PFX' 250 68 70 $true
$chkExportCer = New-CheckBox 'CER' 340 68 70 $true
$chkExportPem = New-CheckBox 'PEM' 430 68 80 $false
$chkExportKey = New-CheckBox 'KEY' 520 68 80 $false
$groupExport.Controls.Add($chkExportPfx)
$groupExport.Controls.Add($chkExportCer)
$groupExport.Controls.Add($chkExportPem)
$groupExport.Controls.Add($chkExportKey)

$groupExport.Controls.Add((New-Label 'PFX Passwort:' 20 105))
$txtPassword = New-TextBox 250 103 300 ''
$txtPassword.UseSystemPasswordChar = $true
$groupExport.Controls.Add($txtPassword)

$chkTrustRoot = New-CheckBox 'Zusätzlich in Trusted Root importieren' 590 102 285 $false
$groupExport.Controls.Add($chkTrustRoot)

$cmbRootStore = New-ComboBox 880 101 200 @('CurrentUser\Root','LocalMachine\Root') 'CurrentUser\Root'
$cmbRootStore.Anchor = 'Top,Right'
$groupExport.Controls.Add($cmbRootStore)

$btnCreate = New-Object System.Windows.Forms.Button
$btnCreate.Text = 'Zertifikat erstellen'
$btnCreate.Location = New-Object System.Drawing.Point(20, 640)
$btnCreate.Size = New-Object System.Drawing.Size(190, 36)
$btnCreate.BackColor = [System.Drawing.Color]::FromArgb(0,120,215)
$btnCreate.ForeColor = [System.Drawing.Color]::White
$btnCreate.FlatStyle = 'Flat'
$tabCreate.Controls.Add($btnCreate)

$btnOpenFolder = New-Object System.Windows.Forms.Button
$btnOpenFolder.Text = 'Export-Ordner öffnen'
$btnOpenFolder.Location = New-Object System.Drawing.Point(230, 640)
$btnOpenFolder.Size = New-Object System.Drawing.Size(180, 36)
$btnOpenFolder.BackColor = [System.Drawing.Color]::FromArgb(255,255,255)
$btnOpenFolder.ForeColor = [System.Drawing.Color]::FromArgb(20,54,96)
$btnOpenFolder.FlatStyle = 'Flat'
$tabCreate.Controls.Add($btnOpenFolder)

# Manage Tab
$manageTop = New-Object System.Windows.Forms.GroupBox
$manageTop.Text = 'Filter'
$manageTop.Location = New-Object System.Drawing.Point(15, 15)
$manageTop.Size = New-Object System.Drawing.Size(1110, 78)
$manageTop.Anchor = 'Top,Left,Right'
$manageTop.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$manageTop.BackColor = [System.Drawing.Color]::FromArgb(248,250,252)
$manageTop.ForeColor = [System.Drawing.Color]::FromArgb(20,54,96)
$tabManage.Controls.Add($manageTop)

$manageTop.Controls.Add((New-Label 'Store:' 20 33 60))
$cmbListStore = New-ComboBox 90 30 260 @('Cert:\CurrentUser\My','Cert:\CurrentUser\Root','Cert:\LocalMachine\My','Cert:\LocalMachine\Root') 'Cert:\CurrentUser\My'
$manageTop.Controls.Add($cmbListStore)

$manageTop.Controls.Add((New-Label 'Suche:' 380 33 60))
$txtSearch = New-TextBox 450 30 360 ''
$txtSearch.Anchor = 'Top,Left,Right'
$manageTop.Controls.Add($txtSearch)

$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text = 'Aktualisieren'
$btnRefresh.Location = New-Object System.Drawing.Point(835, 28)
$btnRefresh.Size = New-Object System.Drawing.Size(120, 30)
$btnRefresh.Anchor = 'Top,Right'
$btnRefresh.BackColor = [System.Drawing.Color]::FromArgb(20,120,190)
$btnRefresh.ForeColor = [System.Drawing.Color]::White
$btnRefresh.FlatStyle = 'Flat'
$manageTop.Controls.Add($btnRefresh)

$btnDelete = New-Object System.Windows.Forms.Button
$btnDelete.Text = 'Ausgewähltes löschen'
$btnDelete.Location = New-Object System.Drawing.Point(970, 28)
$btnDelete.Size = New-Object System.Drawing.Size(130, 30)
$btnDelete.Anchor = 'Top,Right'
$btnDelete.BackColor = [System.Drawing.Color]::FromArgb(190,60,60)
$btnDelete.ForeColor = [System.Drawing.Color]::White
$btnDelete.FlatStyle = 'Flat'
$manageTop.Controls.Add($btnDelete)

$listCerts = New-Object System.Windows.Forms.ListView
$listCerts.Location = New-Object System.Drawing.Point(15, 105)
$listCerts.Size = New-Object System.Drawing.Size(1110, 390)
$listCerts.Anchor = 'Top,Bottom,Left,Right'
$listCerts.View = 'Details'
$listCerts.FullRowSelect = $true
$listCerts.GridLines = $true
$listCerts.MultiSelect = $false
$listCerts.HideSelection = $false
$listCerts.BackColor = [System.Drawing.Color]::White
$listCerts.ForeColor = [System.Drawing.Color]::Black
$listCerts.Font = New-Object System.Drawing.Font('Segoe UI', 9)

[void]$listCerts.Columns.Add('Subject', 300)
[void]$listCerts.Columns.Add('Friendly Name', 170)
[void]$listCerts.Columns.Add('Thumbprint', 280)
[void]$listCerts.Columns.Add('Ablaufdatum', 135)
[void]$listCerts.Columns.Add('Tage', 65)
[void]$listCerts.Columns.Add('Private Key', 85)
[void]$listCerts.Columns.Add('Issuer', 250)
[void]$listCerts.Columns.Add('SAN', 500)

$tabManage.Controls.Add($listCerts)

$txtDetails = New-Object System.Windows.Forms.TextBox
$txtDetails.Location = New-Object System.Drawing.Point(15, 510)
$txtDetails.Size = New-Object System.Drawing.Size(1110, 80)
$txtDetails.Anchor = 'Bottom,Left,Right'
$txtDetails.Multiline = $true
$txtDetails.ReadOnly = $true
$txtDetails.ScrollBars = 'Vertical'
$txtDetails.Font = New-Object System.Drawing.Font('Consolas', 9)
$tabManage.Controls.Add($txtDetails)

# Log
$txtLog = New-Object System.Windows.Forms.TextBox
$txtLog.Location = New-Object System.Drawing.Point(20, 835)
$txtLog.Size = New-Object System.Drawing.Size(1160, 200)
$txtLog.Anchor = 'Bottom,Left,Right'
$txtLog.Multiline = $true
$txtLog.ScrollBars = 'Vertical'
$txtLog.ReadOnly = $true
$txtLog.BackColor = [System.Drawing.Color]::White
$txtLog.Font = New-Object System.Drawing.Font('Consolas', 9)
$form.Controls.Add($txtLog)

$btnClearLog = New-Object System.Windows.Forms.Button
$btnClearLog.Text = 'Log leeren'
$btnClearLog.Location = New-Object System.Drawing.Point(1060, 43)
$btnClearLog.Size = New-Object System.Drawing.Size(120, 28)
$btnClearLog.Anchor = 'Top,Right'
$form.Controls.Add($btnClearLog)

function Refresh-CertList {
    try {
        $store = $null
        if ($cmbListStore -and $cmbListStore.SelectedItem) {
            $store = $cmbListStore.SelectedItem.ToString()
        }

        if ([string]::IsNullOrWhiteSpace($store)) {
            $store = 'Cert:\CurrentUser\My'
        }

        $search = ''
        if ($txtSearch) {
            $search = $txtSearch.Text.Trim()
        }

        if ($store -like 'Cert:\LocalMachine*' -and -not (Test-IsAdmin)) {
            Write-GuiLog -TextBox $txtLog -Level 'WARN' -Message "LocalMachine-Store kann ohne Adminrechte eingeschränkt sein: $store"
        }

        $rows = New-Object System.Collections.Generic.List[object]

        if (Test-Path $store) {
            $certs = @(Get-ChildItem -Path $store -ErrorAction Stop)

            foreach ($cert in $certs) {
                if (-not $cert) { continue }

                $san = ''
                try {
                    foreach ($ext in @($cert.Extensions)) {
                        if ($ext -and $ext.Oid -and $ext.Oid.Value -eq '2.5.29.17') {
                            $san = $ext.Format($false)
                            break
                        }
                    }
                } catch {}

                $daysLeft = 0
                try { $daysLeft = [int][Math]::Floor(($cert.NotAfter - (Get-Date)).TotalDays) } catch {}

                $obj = [pscustomobject]@{
                    Store         = $store
                    Subject       = [string]$cert.Subject
                    FriendlyName  = [string]$cert.FriendlyName
                    Thumbprint    = [string]$cert.Thumbprint
                    NotBefore     = $cert.NotBefore.ToString('yyyy-MM-dd HH:mm')
                    NotAfter      = $cert.NotAfter.ToString('yyyy-MM-dd HH:mm')
                    DaysLeft      = $daysLeft
                    HasPrivateKey = [string]$cert.HasPrivateKey
                    Issuer        = [string]$cert.Issuer
                    SAN           = [string]$san
                }

                if ([string]::IsNullOrWhiteSpace($search)) {
                    [void]$rows.Add($obj)
                }
                else {
                    $haystack = @($obj.Subject, $obj.FriendlyName, $obj.Thumbprint, $obj.SAN, $obj.Issuer) -join ' '
                    if ($haystack -like "*$search*") {
                        [void]$rows.Add($obj)
                    }
                }
            }
        }

        $listCerts.BeginUpdate()
        $listCerts.Items.Clear()

        foreach ($r in $rows) {
            $item = New-Object System.Windows.Forms.ListViewItem([string]$r.Subject)
            [void]$item.SubItems.Add([string]$r.FriendlyName)
            [void]$item.SubItems.Add([string]$r.Thumbprint)
            [void]$item.SubItems.Add([string]$r.NotAfter)
            [void]$item.SubItems.Add([string]$r.DaysLeft)
            [void]$item.SubItems.Add([string]$r.HasPrivateKey)
            [void]$item.SubItems.Add([string]$r.Issuer)
            [void]$item.SubItems.Add([string]$r.SAN)
            $item.Tag = $r

            if ([int]$r.DaysLeft -lt 0) {
                $item.BackColor = [System.Drawing.Color]::FromArgb(255,225,225)
            }
            elseif ([int]$r.DaysLeft -le 30) {
                $item.BackColor = [System.Drawing.Color]::FromArgb(255,245,210)
            }

            [void]$listCerts.Items.Add($item)
        }

        $listCerts.EndUpdate()
        Write-GuiLog -TextBox $txtLog -Level 'INFO' -Message "Zertifikatsliste aktualisiert: $store / Treffer: $($rows.Count)"
    }
    catch {
        try { if ($listCerts) { $listCerts.EndUpdate() } } catch {}
        Write-GuiLog -TextBox $txtLog -Level 'ERROR' -Message "Fehler beim Abruf der Zertifikatsliste: $($_.Exception.Message)"
    }
}

$btnBrowse.Add_Click({
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = 'Export-Ordner auswählen'
    $dialog.SelectedPath = $txtExportPath.Text

    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $txtExportPath.Text = $dialog.SelectedPath
    }
})

$btnOpenFolder.Add_Click({
    if (-not (Test-Path $txtExportPath.Text)) {
        New-Item -Path $txtExportPath.Text -ItemType Directory -Force | Out-Null
    }
    Start-Process explorer.exe $txtExportPath.Text
})

$btnClearLog.Add_Click({ $txtLog.Clear() })
$btnRefresh.Add_Click({ Refresh-CertList })
$txtSearch.Add_TextChanged({ Refresh-CertList })
$cmbListStore.Add_SelectedIndexChanged({ Refresh-CertList })

$listCerts.Add_SelectedIndexChanged({
    try {
        if ($listCerts.SelectedItems.Count -gt 0) {
            $r = $listCerts.SelectedItems[0].Tag
            $txtDetails.Text = @(
                "Store: $($r.Store)",
                "Subject: $($r.Subject)",
                "FriendlyName: $($r.FriendlyName)",
                "Thumbprint: $($r.Thumbprint)",
                "NotBefore: $($r.NotBefore)",
                "NotAfter: $($r.NotAfter) / DaysLeft: $($r.DaysLeft)",
                "HasPrivateKey: $($r.HasPrivateKey)",
                "SAN: $($r.SAN)"
            ) -join "`r`n"
        }
    } catch {}
})

$btnDelete.Add_Click({
    try {
        if ($listCerts.SelectedItems.Count -eq 0) {
            throw 'Kein Zertifikat ausgewählt.'
        }

        $r = $listCerts.SelectedItems[0].Tag
        if (-not $r) {
            throw 'Ausgewähltes Zertifikat konnte nicht gelesen werden.'
        }

        $store = [string]$r.Store
        $thumb = [string]$r.Thumbprint
        $subject = [string]$r.Subject

        if ($store -like 'Cert:\LocalMachine*' -and -not (Test-IsAdmin)) {
            throw 'Löschen aus LocalMachine benötigt Administratorrechte.'
        }

        $confirm = [System.Windows.Forms.MessageBox]::Show(
            "Zertifikat wirklich löschen?`r`n`r`nSubject: $subject`r`nThumbprint: $thumb",
            'Löschen bestätigen',
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )

        if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) {
            return
        }

        Remove-Item -Path (Join-Path $store $thumb) -Force
        Write-GuiLog -TextBox $txtLog -Level 'SUCCESS' -Message "Zertifikat gelöscht: $thumb"
        Refresh-CertList
    }
    catch {
        Write-GuiLog -TextBox $txtLog -Level 'ERROR' -Message $_.Exception.Message
        [System.Windows.Forms.MessageBox]::Show(
            $_.Exception.Message,
            'Fehler',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
    }
})

$btnCreate.Add_Click({
    try {
        $btnCreate.Enabled = $false

        $cn = $txtCN.Text.Trim()
        $ou = $txtOU.Text.Trim()
        $org = $txtO.Text.Trim()
        $city = $txtL.Text.Trim()
        $state = $txtST.Text.Trim()
        $country = $txtC.Text.Trim()
        $email = $txtE.Text.Trim()
        $sanRaw = $txtDns.Text.Trim()
        $friendlyName = $txtFriendly.Text.Trim()
        $exportPath = $txtExportPath.Text.Trim()
        $years = [int]$numYears.Value
        $keyLength = [int]$cmbKeyLength.SelectedItem
        $hash = $cmbHash.SelectedItem.ToString()
        $storeSelection = $cmbStore.SelectedItem.ToString()
        $exportPfx = $chkExportPfx.Checked
        $exportCer = $chkExportCer.Checked
        $exportPem = $chkExportPem.Checked
        $exportKey = $chkExportKey.Checked
        $trustRoot = $chkTrustRoot.Checked
        $rootStoreSelection = $cmbRootStore.SelectedItem.ToString()

        if ([string]::IsNullOrWhiteSpace($cn)) {
            throw 'Common Name darf nicht leer sein.'
        }

        if (-not [string]::IsNullOrWhiteSpace($country) -and $country.Length -ne 2) {
            throw 'Country / C muss aus genau 2 Buchstaben bestehen, z.B. DE.'
        }

        $subjectName = New-X500Subject -CN $cn -OU $ou -O $org -L $city -ST $state -C $country -E $email

        if (-not $subjectName) {
            throw 'Subject konnte nicht erstellt werden.'
        }

        if (-not (Test-Path $exportPath)) {
            New-Item -Path $exportPath -ItemType Directory -Force | Out-Null
            Write-GuiLog -TextBox $txtLog -Level 'INFO' -Message "Export-Ordner erstellt: $exportPath"
        }

        if ($storeSelection -like 'LocalMachine*' -and -not (Test-IsAdmin)) {
            throw 'LocalMachine-Store benötigt Administratorrechte.'
        }

        if ($trustRoot -and $rootStoreSelection -like 'LocalMachine*' -and -not (Test-IsAdmin)) {
            throw 'Trusted Root LocalMachine benötigt Administratorrechte.'
        }

        if ($exportPfx -and [string]::IsNullOrWhiteSpace($txtPassword.Text)) {
            throw 'Für den PFX-Export muss ein Passwort angegeben werden.'
        }

        $sanEntries = @()

        if (-not [string]::IsNullOrWhiteSpace($sanRaw)) {
            $sanEntries += $sanRaw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        }

        if ($sanEntries -notcontains $cn) {
            $sanEntries = @($cn) + $sanEntries
        }

        $sanEntries = $sanEntries | Select-Object -Unique

        $dnsNames = @()
        $ipAddresses = @()

        foreach ($entry in $sanEntries) {
            $ipObj = $null
            if ([System.Net.IPAddress]::TryParse($entry, [ref]$ipObj)) {
                $ipAddresses += $entry
            } else {
                $dnsNames += $entry
            }
        }

        if ($dnsNames.Count -eq 0) {
            $dnsNames += $cn
        }

        $certStoreLocation = "Cert:\$storeSelection"
        $notAfter = (Get-Date).AddYears($years)

        $textExtensions = @()
        $textExtensions += Get-EkuText `
            -ServerAuth $chkServerAuth.Checked `
            -ClientAuth $chkClientAuth.Checked `
            -CodeSigning $chkCodeSigning.Checked `
            -DocumentSigning $chkDocumentSigning.Checked

        $sanExtension = Get-SanTextExtension -DnsNames $dnsNames -IpAddresses $ipAddresses
        if ($sanExtension) {
            $textExtensions += $sanExtension
        }

        $textExtensions += '2.5.29.19={text}CA=false'

        Write-GuiLog -TextBox $txtLog -Level 'INFO' -Message 'Erstelle Zertifikat...'
        Write-GuiLog -TextBox $txtLog -Level 'INFO' -Message "Subject: $subjectName"
        Write-GuiLog -TextBox $txtLog -Level 'INFO' -Message "CN: $cn"
        Write-GuiLog -TextBox $txtLog -Level 'INFO' -Message "DNS-SANs: $($dnsNames -join ', ')"
        if ($ipAddresses.Count -gt 0) {
            Write-GuiLog -TextBox $txtLog -Level 'INFO' -Message "IP-SANs: $($ipAddresses -join ', ')"
        }
        Write-GuiLog -TextBox $txtLog -Level 'INFO' -Message "Store: $certStoreLocation"

        $baseParams = @{
            Subject           = $subjectName
            CertStoreLocation = $certStoreLocation
            KeyAlgorithm      = 'RSA'
            KeyLength         = $keyLength
            HashAlgorithm     = $hash
            NotAfter          = $notAfter
            KeyExportPolicy   = 'Exportable'
            FriendlyName      = $friendlyName
            TextExtension     = $textExtensions
        }

        $cert = New-CertificateWithFallback -BaseParams $baseParams -LogBox $txtLog

        Write-GuiLog -TextBox $txtLog -Level 'SUCCESS' -Message "Zertifikat erstellt. Thumbprint: $($cert.Thumbprint)"

        $safeName = Get-SafeFileName -Name $cn
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $baseFile = Join-Path $exportPath "$safeName`_$timestamp"
        $cerPath = "$baseFile.cer"

        if ($exportCer -or $exportPem -or $trustRoot) {
            Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null

            if ($exportCer) {
                Write-GuiLog -TextBox $txtLog -Level 'SUCCESS' -Message "CER exportiert: $cerPath"
            }
        }

        if ($exportPem) {
            $pemPath = "$baseFile.pem"
            Convert-CerToPem -CerPath $cerPath -PemPath $pemPath
            Write-GuiLog -TextBox $txtLog -Level 'SUCCESS' -Message "PEM exportiert: $pemPath"
        }

        if ($exportPfx) {
            $pfxPath = "$baseFile.pfx"
            $securePassword = ConvertTo-SecureString -String $txtPassword.Text -Force -AsPlainText
            Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $securePassword -Force | Out-Null
            Write-GuiLog -TextBox $txtLog -Level 'SUCCESS' -Message "PFX exportiert: $pfxPath"
        }

        if ($exportKey) {
            $keyPath = "$baseFile.key"
            Export-PrivateKeyToPem -Certificate $cert -KeyPath $keyPath
            Write-GuiLog -TextBox $txtLog -Level 'SUCCESS' -Message "Private Key exportiert: $keyPath"
        }

        if ($trustRoot) {
            $rootStore = "Cert:\$rootStoreSelection"
            Import-Certificate -FilePath $cerPath -CertStoreLocation $rootStore | Out-Null
            Write-GuiLog -TextBox $txtLog -Level 'SUCCESS' -Message "Zertifikat in Trusted Root importiert: $rootStore"
        }

        if ((-not $exportCer) -and (-not $exportPem) -and (-not $trustRoot) -and (Test-Path $cerPath)) {
            Remove-Item $cerPath -Force -ErrorAction SilentlyContinue
        }

        Write-GuiLog -TextBox $txtLog -Level 'SUCCESS' -Message 'Fertig.'
        Refresh-CertList
    }
    catch {
        Write-GuiLog -TextBox $txtLog -Level 'ERROR' -Message $_.Exception.Message
        [System.Windows.Forms.MessageBox]::Show(
            $_.Exception.Message,
            'Fehler',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
    }
    finally {
        $btnCreate.Enabled = $true
    }
})

Write-GuiLog -TextBox $txtLog -Level 'INFO' -Message 'Tool gestartet.'
Write-GuiLog -TextBox $txtLog -Level 'INFO' -Message 'Zertifikatsliste nutzt eine robuste ListView-Anzeige ohne DataTable-Indexzugriff.'
Write-GuiLog -TextBox $txtLog -Level 'INFO' -Message 'Subject-Felder CN, OU, O, L, ST, C und E werden unterstützt.'
Write-GuiLog -TextBox $txtLog -Level 'INFO' -Message 'DNS/IP-SANs werden ohne -IPAddress Parameter erstellt.'
Write-GuiLog -TextBox $txtLog -Level 'INFO' -Message 'Für produktive interne Dienste besser AD CS oder eine interne CA verwenden.'

try {
    if (-not (Test-Path 'C:\install\Zertifikate')) {
        New-Item -Path 'C:\install\Zertifikate' -ItemType Directory -Force | Out-Null
        Write-GuiLog -TextBox $txtLog -Level 'INFO' -Message 'Standardordner erstellt: C:\install\Zertifikate'
    }
} catch {
    Write-GuiLog -TextBox $txtLog -Level 'WARN' -Message "Standardordner konnte nicht erstellt werden: $($_.Exception.Message)"
}

Refresh-CertList

[void]$form.ShowDialog()
