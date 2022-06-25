##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SYS.2.2.3.nasl 12387 2018-11-16 14:06:23Z cfischer $
#
# IT-Grundschutz Baustein: SYS.2.2.3 Clients unter Windows 10
#
# Authors:
# Emanuel Moss <emanuel.moss@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109034");
  script_version("$Revision: 12387 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 15:06:23 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-12-13 07:42:28 +0200 (Wed, 13 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('SYS.2.2.3 Clients unter Windows 10');
  script_xref(name:"URL", value:"https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_2_2_3_Clients_unter_Windows_10.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB-ITG");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_WMI_Antivir.nasl", "GSHB/GSHB_SMB_UAC_Config.nasl", "GSHB/GSHB_WMI_EFS.nasl");

  script_tag(name:"summary", value:"Ziel dieses Bausteins ist der Schutz von Informationen,
  die durch und auf Windows 10-Clients verarbeiten werden.");

  exit(0);
}

include("smb_nt.inc");
include("misc_func.inc");

Windows_Version = get_kb_item("WMI/WMI_OSVER");
Windows_Name = get_kb_item("WMI/WMI_OSNAME");
Windows_Architecture = get_kb_item("WMI/WMI_OSArchitecture");

if( Windows_Version != "10" && "windows 10" >!< tolower(Windows_Name) ){
  for( i=1; i<=25; i++){
    set_kb_item(name:"GSHB/SYS.2.2.3.A" + i + "/result", value:"nicht zutreffend");
    set_kb_item(name:"GSHB/SYS.2.2.3.A" + i + "/desc", value:"Auf dem Host ist kein Microsoft Windows 10 Betriebsystem installiert.");
  }
  log_message(data:"Auf dem Host ist kein Microsoft Windows 10 Betriebsystem installiert,
oder es konnte keine Verbindung zum Host hergestellt werden.");
  exit(0);
}

host    = get_host_ip();
usrname = kb_smb_login();
domain  = kb_smb_domain();
if( domain ){
  usrname_handle = domain + '\\' + usrname;
  usrname_WmiCmd = domain + '/' + usrname;
}
passwd = kb_smb_password();
handle = wmi_connect(host:host, username:usrname_handle, password:passwd, ns:'root\\rsop\\computer');
if( !handle ){
  for( i=1; i<=25; i++){
    set_kb_item(name:"GSHB/SYS.2.2.3.A" + i + "/result", value:"error");
    set_kb_item(name:"GSHB/SYS.2.2.3.A" + i + "/desc", value:"Es konnte keine Verbindung zum Host hergestellt werden.");
  }
  log_message(data:"Es konnte keine Verbindung zum Host hergestellt werden.");
  exit(0);
}

disabled_win_cmd_exec = get_kb_item("win/lsc/disable_win_cmd_exec");
disabled_win_cmd_exec_report = "Die Verwendung der benoetigten win_cmd_exec Funktion wurde in 'Options for Local Security Checks (OID: 1.3.6.1.4.1.25623.1.0.100509)' manuell deaktiviert.";

# SYS.2.2.3.A1 Planung des Einsatzes von Cloud-Diensten
SYS_2_2_3_A1 = 'SYS.2.2.3.A1 Planung des Einsatzes von Cloud-Diensten:\n';
SYS_2_2_3_A1 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.2.2.3.A2 Geeignete Auswahl einer Windows 10-Version und Beschaffung
SYS_2_2_3_A2 = 'SYS.2.2.3.A2 Geeignete Auswahl einer Windows 10-Version und Beschaffung:\n';
result = 'Diese Vorgabe muss manuell überprüft werden.';
if( Windows_Architecture ){
  desc = 'Windows 10 wird in einer ' + Windows_Architecture + ' Architektur betrieben.\n';
}else{
  desc = 'Die Windows 10 Architektur (32 / 64 Bit) konnte nicht bestimmt werden.\n';
}
desc += 'Auf dem Host läuft folgendes Betriebssystem: ' + Windows_Name + '.\n';

SYS_2_2_3_A2 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.3.A2/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.3.A2/desc", value:desc);

# SYS.2.2.3.A3 Geeignetes Patch- und Änderungsmanagement
SYS_2_2_3_A3 = 'SYS.2.2.3.A3 Geeignetes Patch- und Änderungsmanagement:\n';
SYS_2_2_3_A3 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.2.2.3.A4 Telemetrie und Datenschutzeinstellungen
SYS_2_2_3_A4 = 'SYS.2.2.3.A4 Telemetrie und Datenschutzeinstellungen:\n';
SYS_2_2_3_A4 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.2.2.3.A5 Schutz vor Schadsoftware
SYS_2_2_3_A5 = 'SYS.2.2.3.A5 Schutz vor Schadsoftware:\n';
result = 'erfüllt';
SecurityCenter2 = get_kb_item("WMI/Antivir/SecurityCenter2");
SecurityCenter2 = split(SecurityCenter2, keep:FALSE);
if( max_index(SecurityCenter2) <= 1 ){
  desc = 'Es konnte kein Viren-Schutzprogramm im Security Center gefunden werden.\n';
  desc += 'Stellen Sie sicher, dass gleich- oder höherwertige Maßnahmen zum Schutz des\n';
  desc += 'IT-Sytems vor einer Infektion mit Schadsoftware getroffen wurde.\n';
  result = 'nicht erfüllt';
}else{
  desc = 'Folgende Schutzprogramme sind installiert:\n';

  # nb: get state of each AntiVir program (can be more than one)
  foreach line (SecurityCenter2){
    line = split(line, sep:'|', keep:FALSE);

    # skip header
    if( tolower(line[0]) == 'displayname' ){
      continue;
    }

    desc += line[0] + '\n';
    ProductState = dec2hex(num:line[4]);

    ProtectionStatus = hexstr(substr( ProductState, 1, 1));
    if( ProtectionStatus == "00" || ProtectionStatus == "01" ){
      ProtectionStatus_Res = "nicht aktiv";
    }else if( ProtectionStatus == "10" || ProtectionStatus == "11"){
      ProtectionStatus_Res = "aktiv";
    }else{
      ProtectionStatus_Res = "unbekannt";
    }

    UpToDate = hexstr(substr(ProductState, 2, 2));
    if( UpToDate == "00" ){
      UpToDate_Res = "aktuell";
    }else if( UpToDate == "10" ){
      UpToDate_Res = "veraltet";
    }else{
      UpToDate_Res = "unbekannt";
    }

    desc += 'Status: ' + ProtectionStatus_Res + '\n';
    desc += 'Zeitstempel: ' + UpToDate_Res + '\n';
  }
}

SYS_2_2_3_A5 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.3.A5/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.3.A5/desc", value:desc);

# SYS.2.2.3.A6 Integration von Online-Konten in das Betriebssystem [Benutzer]
SYS_2_2_3_A6 = 'SYS.2.2.3.A6 Integration von Online-Konten in das Betriebssystem [Benutzer]:\n';
result = 'erfüllt';
NoConnectedUser = registry_get_dword(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", item:"NoConnectedUser");
if( NoConnectedUser == "3" ){
  desc = 'Benutzer können sich nicht mit Microsoft-Konten einloggen oder diese hinzufügen.\n';
}else if( NoConnectedUser == "2" ){
  desc = 'Benutzer können sich nicht mit Microsoft-Konten einloggen, es können aber neue hinzugefügt werden. Dies muss deaktiviert sein.\n';
  result = 'nicht erfüllt';
}else if( NoConnectedUser == "1" ){
  desc = 'Benutzer können sich mit Microsoft-Konten einloggen, es können aber keine neue hinzugefügt werden. Dies muss deaktiviert sein.\n';
  result = 'nicht erfüllt';
}else{
  desc = 'Benutzer können sich mit Microsoft-Konten einloggen und diese hinzufügen. Dies muss deaktiviert sein.\n';
  result = 'nicht erfüllt';
}

SwitchToMicrosoftAccount = registry_get_dword(key:"SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowYourAccount", value:"value");
if( SwitchToMicrosoftAccount == "0" ){
  desc += 'Benutzer können ihr Konto nicht zu einem Microsoft-Konto ändern.\n';
}else{
  desc += 'Benutzer können ihr Konto zu einem Microsoft-Konto ändern. Dies sollte deaktiviert werden.\n';
  result = 'nicht erfüllt';
}

query = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeDenyInteractiveLogonRight' AND precedence=1";
SeDenyInteractiveLogonRight = wmi_query(wmi_handle:handle, query:query);
if( ! SeDenyInteractiveLogonRight ){
  desc += 'Es konnten keine Benutzer gefunden werden, denen die lokale Anmeldung verweigert wird (GPO "Lokale Anmeldung Verweigern").\n';
}else{
  SeDenyInteractiveLogonRight = split(SeDenyInteractiveLogonRight, keep:FALSE);
  desc += 'Folgenden Benutzern wird die lokale Anmeldung verweigert (GPO "Lokale Anmeldung Verweigern"):\n';
  foreach line (SeDenyInteractiveLogonRight){
    line = split(line, sep:'|', keep:FALSE);
    if( tolower(line[0]) == 'accountlist' ){
      continue;
    }

    for( y=0; y<=max_index(line)-3; y++ ){
      desc += line[y];
      if( y == max_index(line)-3 ){
        desc += '\n';
      }else{
        desc += ', ';
      }
    }
  }
}

query = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeInteractiveLogonRight' AND precedence=1";
SeInteractiveLogonRight = wmi_query(wmi_handle:handle, query:query);
if( ! SeInteractiveLogonRight ){
  desc += 'Es konnten keine Benutzer gefunden werden, denen die lokale Anmeldung zugelassen wird (GPO "Lokale Anmeldung Zulassen").\n';
}else{
  SeInteractiveLogonRight = split(SeInteractiveLogonRight, keep:FALSE);
  desc += 'Folgenden Benutzern wird die lokale Anmeldung zugelassen (GPO "Lokale Anmeldung Zulassen"):\n';
  foreach line (SeInteractiveLogonRight){
    line = split(line, sep:'|', keep:FALSE);
    if( tolower(line[0]) == 'accountlist' ){
      continue;
    }

    for( y=0; y<=max_index(line)-3; y++ ){
      desc += line[y];
      if( y == max_index(line)-3 ){
        desc += '\n';
      }else{
        desc += ', ';
      }
    }
  }
}

SYS_2_2_3_A6 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.3.A6/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.3.A6/desc", value:desc);

# SYS.2.2.3.A7 Lokale Sicherheitsrichtlinien
SYS_2_2_3_A7 = 'SYS.2.2.3.A7 Lokale Sicherheitsrichtlinien:\n';
SYS_2_2_3_A7 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.2.2.3.A8 Zentrale Verwaltung der Sicherheitsrichtlinien von Clients
SYS_2_2_3_A8 = 'SYS.2.2.3.A8 Zentrale Verwaltung der Sicherheitsrichtlinien von Clients:\n';
SYS_2_2_3_A8 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.2.2.3.A9 Sichere zentrale Authentisierung der Windows-Clients
SYS_2_2_3_A9 = 'SYS.2.2.3.A9 Sichere zentrale Authentisierung der Windows-Clients:\n';
SYS_2_2_3_A9 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.2.2.3.A10 Konfiguration zum Schutz von Anwendungen in Windows 10
SYS_2_2_3_A10 = 'SYS.2.2.3.A10 Konfiguration zum Schutz von Anwendungen in Windows 10:\n';
result = 'erfüllt';

if( ! disabled_win_cmd_exec ){
  res = win_cmd_exec(cmd:"bcdedit /enum", password:passwd, username:usrname_WmiCmd);
  if( res ){
    res = split(res, keep:FALSE);
    foreach line ( res ){
      nx_status = eregmatch(string:line, pattern:"nx[ ]+([a-z,A-Z]+)");
      if( nx_status[1] ){
        DEP = nx_status[1];
        break;
      }
    }
  }
}

if( DEP ){
  desc = 'Die Dateiausführungsverhinderung ist in Einstellung: ' + DEP + '.';
  if( tolower(DEP) != "optout" ){
    desc += ' Dies sollte auf die Einstellung "OptOut" geändert werden.';
    result = 'nicht erfüllt';
  }
  desc += '\n';
}else{
  desc = 'Die Einstellung der Dateiausführungsverhinderung konnte nicht bestimmt werden.';
  if( disabled_win_cmd_exec ){
    desc += " " + disabled_win_cmd_exec_report;
  }
  desc += '\n';
  result = 'error';
}

SYS_2_2_3_A10 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.3.A10/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.3.A10/desc", value:desc);

# SYS.2.2.3.A11 Schutz der Anmeldeinformationen in Windows 10
SYS_2_2_3_A11 = 'SYS.2.2.3.A11 Schutz der Anmeldeinformationen in Windows 10:\n';
result = 'erfüllt';
if( "enterprise" >< tolower(Windows_Name) ){
  VBS = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", item:"EnableVirtualizationBasedSecurity");
  RequirePlatformSecFeatures = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", item:"RequirePlatformSecurityFeatures");
  HypervisorEnforcedCodeIntegrity = registry_get_dword(key:"keySOFTWARE\Policies\Microsoft\Windows\DeviceGuard", item:"HypervisorEnforcedCodeIntegrity");
  HVCIMATRequired = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", item:"HVCIMATRequired");
  LsaCfgFlags = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", item:"LsaCfgFlags");

  if( VBS == "1" ){
    desc = 'Virtualization Based Security (VBS) ist aktiviert.\n';
  }else{
    desc = 'Virtualization Based Security (VBS) ist nicht aktiviert.\n';
    desc += 'Dies sollte aktiviert werden, um den Virtual Security Mode zu aktivieren.\n';
    result = 'nicht erfüllt';
  }

  if( RequirePlatformSecFeatures == "3" ){
    desc += 'VBS ist mit Direct-Memory-Access-Schutz aktiviert.\n';
  }else if( RequirePlatformSecFeatures == "1" ){
    desc += 'VBS ist ohne Direct-Memory-Access-Schutz aktiviert.\n';
  }

  if( HypervisorEnforcedCodeIntegrity == "0" ){
    desc += '"Virtualization Based Protection of Code Integrity" ist nicht aktiviert.\n';
  }else if( HypervisorEnforcedCodeIntegrity == "1" ){
    desc += '"Virtualization Based Protection of Code Integrity" ist mit UEFI Sperre aktiviert.\n';
  }else if( HypervisorEnforcedCodeIntegrity == "2" ){
    desc += '"Virtualization Based Protection of Code Integrity" ist ohne UEFI Sperre aktiviert.\n';
  }else if( HypervisorEnforcedCodeIntegrity == "3" ){
    desc += '"Virtualization Based Protection of Code Integrity" ist nicht konfiguriert.\n';
  }

  if( HVCIMATRequired == "1" ){
    desc += 'Die Option "Require UEFI Memory Attributes Table" ist aktiviert.\n';
  }else if( HVCIMATRequired == "0" ){
    desc += 'Die Option "Require UEFI Memory Attributes Table" ist nicht aktiviert. Dies kann dazu führen,\n';
    desc += 'dass inkompatible Geräte einen Absturz des Systems verursachen. Diese Option sollte daher aktiviert werden.\n';
    result = 'nicht erfüllt';
  }

  if( LsaCfgFlags == "0" ){
    LSASS = registry_get_dword(key:"SYSTEM\CurrentControlSet\Control\Lsa", item:"RunAsPPL");
    if( LSASS == "1" ){
      desc += 'Credential Guard ist nicht aktiviert, jedoch ist PPL aktiviert. Es sollte überlegt werden, Credential Guard einzusetzen.\n';
    }else{
      desc += 'Credential Guard ist nicht aktiviert. Dies sollte aktiviert werden, da PPL ebenfalls nicht aktiviert ist.\n';
      result = 'nicht erfüllt';
    }
  }else if( LsaCfgFlags == "1" ){
    desc += 'Credential Guard ist mit UEFI Sperre aktiviert.\n';
  }else if( LsaCfgFlags == "2" ){
    desc += 'Credential Guard ist ohne UEFI Sperre aktiviert.\n';
  }else if( LsaCfgFlags == "3" ){
    LSASS = registry_get_dword(key:"SYSTEM\CurrentControlSet\Control\Lsa", item:"RunAsPPL");
    if( LSASS == "1" ){
      desc += 'Credential Guard ist nicht aktiviert, jedoch ist PPL aktiviert. Es sollte überlegt werden, Credential Guard einzusetzen.\n';
    }else{
      desc += 'Credential Guard ist nicht aktiviert. Dies sollte aktiviert werden, da PPL ebenfalls nicht aktiviert ist.\n';
      result = 'nicht erfüllt';
    }
  }

  desc += '\n';
}else{
  desc = 'Diese Vorgabe kann nicht überprüft werden, da keine Enterprise Version installiert ist.\n';
  result = 'nicht zutreffend';
}

SYS_2_2_3_A11 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.3.A11/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.3.A11/desc", value:desc);

# SYS.2.2.3.A12 Datei- und Freigabeberechtigungen
SYS_2_2_3_A12 = 'SYS.2.2.3.A12 Datei- und Freigabeberechtigungen:\n';
SYS_2_2_3_A12 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.2.2.3.A13 Einsatz der SmartScreen-Funktionen
SYS_2_2_3_A13 = 'SYS.2.2.3.A13 Einsatz der SmartScreen-Funktionen:\n';
SmartScreen = registry_get_dword(key:"Software\Policies\Microsoft\Windows\System", item:"EnableSmartScreen");
if( SmartScreen && SmartScreen != "0" ){
  desc = 'Die SmartScreen-Funktion ist aktiviert. Diese sollte deaktiviert werden.\n';
  result = 'nicht erfüllt';
}else{
  desc = 'Die SmartScreen-Funktion ist deaktiviert.\n';
  result = 'erfüllt';
}

SYS_2_2_3_A13 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.3.A13/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.3.A13/desc", value:desc);

# SYS.2.2.3.A14 Einsatz des Sprachassistenten Cortana [Benutzer]
SYS_2_2_3_A14 = 'SYS.2.2.3.A14 Einsatz des Sprachassistenten Cortana:\n';
Cortana = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows\Windows Search", item:"AllowCortana");
if( Cortana == "0" ){
  desc = 'Cortana ist deaktiviert.\n\n';
  result = 'erfüllt';
}else{
  desc = 'Cortana ist aktiviert. Cortana sollte deaktiviert werden.\n\n';
  result = 'nicht erfüllt';
}

SYS_2_2_3_A14 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.3.A14/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.3.A14/desc", value:desc);

# SYS.2.2.3.A15 Einsatz der Synchronisationsmechanismen in Windows 10
SYS_2_2_3_A15 = 'SYS.2.2.3.A15 Einsatz der Synchronisationsmechanismen in Windows 10:\n';
result = 'erfüllt';
DisableSettingSync = registry_get_dword(key:"Software\Policies\Microsoft\Windows\SettingSync", item:"DisableSettingSync");
if( DisableSettingSync == '2' ){
  desc = 'Einstellungen werden nicht synchronisiert.\n';
}else{
  desc = 'Synchronisation der Einstellungen werden nicht unterbunden. ';
  desc += 'Dies sollte verhindert werden (GPO: "Synchronisation verhindern")\n';
  result = 'nicht erfüllt';
}

ConnectedSearchUseWeb = registry_get_dword(key:"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ConnectedSearch", item:"ConnectedSearchUseWeb");
if( ConnectedSearchUseWeb == '0' ){
  desc += 'Bei einer Suche mit Bing werden keine Internetsuchvorschläge einbezogen.\n';
}else{
  desc += 'Bei einer Suche mit Bing werden Internetsuchvorschläge einbezogen. ';
  desc += 'Dies sollte verhindert werden (GPO: "Nicht im Web suchen und keine Webergebnisse anzeigen").\n';
  result = 'nicht erfüllt';
}

ConnectedSearchPrivacy = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows\Windows Search", item:"ConnectedSearchPrivacy");
if( ConnectedSearchPrivacy == '2' ){
  desc += 'Bei einer Suche mit Bing werden lediglich Anwendungsinformationen anonymisiert übertragen.\n';
}else{
  desc += 'Bei einer Suche mit Bing werden Nutzerdaten übertragen. ';
  desc += 'Dies sollte verhindert werden (GPO: "Festlegen der in der Suche freizugebenden Informationen")\n';
  result = 'nicht erfüllt';
}

DisableFileSync = registry_get_dword(key:"Software\Policies\Microsoft\Windows\Skydrive", item:"DisableFileSync");
if( DisableFileSync == '1' ){
  desc += 'OneDrive ist als Speicherort für Dateien deaktiviert.\n';
}else{
  desc += 'OneDrive wird als Speicherort für Dateien nicht verhindert. ';
  desc += 'Dies sollte verhindert werden (GPO: "verwendung von OneDrive für die Datenspeicherung verhindern")\n';
  result = 'nicht erfüllt';
}

DisableLibrariesDefaultSaveToSkyDrive = registry_get_dword(key:"Software\Policies\Microsoft\Windows\Skydrive", item:"DisableLibrariesDefaultSaveToSkyDrive");
if( DisableLibrariesDefaultSaveToSkyDrive == '1' ){
  desc += 'Dateien und Dokumente werden standardmäßig nicht auf OneDrive gespeichert.\n';
}else{
  desc += 'Dateien und Dokumente werden standardmäßig auf OneDrive gespeichert. ';
  desc += 'Dies sollte verhindert werden (GPO: "Dokumente standardmäßig auf OneDrive speichern")\n';
  result = 'nicht erfüllt';
}

WiFiSense = registry_get_dword(key:"Software\Microsoft\wcmsvc\wifinetworkmanager\config", item:"AutoConnectAllowedOEM");
if( WiFiSense == "0" ){
  desc += 'Das Sharing von WLAN-Passwörtern ist deaktiviert.\n\n';
}else{
  desc += 'Das Sharing von WLAN-Passwörtern ist aktiviert oder kann von Benutzern aktiviert werden. ';
  desc += 'Dies sollte deaktiviert werden.\n\n';
  result = 'nicht erfüllt';
}

SYS_2_2_3_A15 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.3.A15/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.3.A15/desc", value:desc);

# SYS.2.2.3.A16 Anbindung von Windows 10 an den Windows Store
SYS_2_2_3_A16 = 'SYS.2.2.3.A16 Anbindung von Windows 10 an den Windows Store:\n';
WindowsStore = registry_get_dword(key:"Software\Policies\Microsoft\WindowsStore", item:"RemoveWindowsStore");
if( WindowsStore == "1" ){
  desc = 'Der Windows Store ist deaktiviert.\n';
  result = 'erfüllt';
}else{
  desc = 'Der Windows Store ist nicht deaktiviert. Dieser sollte, falls nicht benötigt, deaktiviert werden.\n\n';
  result = 'nicht erfüllt';
}

SYS_2_2_3_A16 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.3.A16/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.3.A16/desc", value:desc);

# SYS.2.2.3.A17 Verwendung der automatischen Anmeldung
SYS_2_2_3_A17 = 'SYS.2.2.3.A17 Verwendung der automatischen Anmeldung:\n';
SYS_2_2_3_A17 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.2.2.3.A18 Einsatz der Windows-Remoteunterstützung
SYS_2_2_3_A18 = 'SYS.2.2.3.A18 Einsatz der Windows-Remoteunterstützung:\n';
result = 'erfüllt';
OfferRemoteAssistance = registry_get_dword(key:"Software\policies\Microsoft\Windows NT\Terminal Services", item:"fAllowUnsolicited");
if( OfferRemoteAssistance == "0" ){
  desc = 'Remote-Unterstützung anbieten ist deaktiviert. ';
  desc += 'Eine Remote-Unterstützung kann nur nach einer expliziten Einladung erfolgen.\n';
}else{
  desc = 'Remote-Unterstützung anbieten ist nicht deaktiviert. Dies sollte deaktiviert sein, damit eine ';
  desc += 'Remote-Unterstützung nur nach einer expliziten Einladung erfolgen kann.\n';
  result = 'nicht erfüllt';
}

UsersPermission = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"Shadow");
if( UsersPermission == "0" ){
  desc += 'Die Remote-Kontrolle ist deaktiviert.\n';
}else if( UsersPermission == "1" ){
  desc += 'Eine Remote-Kontrolle bedarf der Zustimmung des Benutzers. Es kann die volle Kontrolle übernommen werden.\n';
}else if( UsersPermission == "2" ){
  desc += 'Eine vollständige Remote-Kontrolle kann ohne Zustimmung des Benutzers erfolgen. Dies sollte deaktiviert werden.\n';
}else if( UsersPermission == "3" ){
  desc += 'Eine Remote-Kontrolle bedarf der Zustimmung des Benutzers. Es kann die Session des Benutzers beobachtet werden.\n';
}else if( UsersPermission == "4" ){
  desc += 'Die Session kann ohne Zustimmung des Benutzers beobachtet werden. Dies sollte deaktiviert werden.\n';
  result = 'nicht erfüllt';
}else{
  desc += 'Die Einstellungen für Remotedesktopdienste konnte nicht ausgelesen werden.\n';
  result = 'error';
}

MaxTicketExpiry = registry_get_dword(key:"Software\policies\Microsoft\Windows NT\Terminal Services", item:"MaxTicketExpiry");
MaxTicketExpiryUnits = registry_get_dword(key:"Software\policies\Microsoft\Windows NT\Terminal Services", item:"MaxTicketExpiryUnits");
if( MaxTicketExpiryUnits == "0" ){
  Unit = " Minuten.";
}else if( MaxTicketExpiryUnits == "1" ){
  Unit = " Stunden.";
}else if( MaxTicketExpiryUnits == "2" ){
  Unit = " Tage.";
}

if( MaxTicketExpiry && Unit ){
  desc += 'Die maximale Gültigkeitsdauer der Einladung beträgt ' + MaxTicketExpiry + MaxTicketExpiryUnits + '\n';
}else{
  desc += 'Es ist keine maximale Gültigkeitsdauer der Einladung konfiguriert. Diese sollte eine angemessene Größe haben.\n';
  result = 'nicht erfüllt';
}

SYS_2_2_3_A18 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.3.A18/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.3.A18/desc", value:desc);

# SYS.2.2.3.A19 Verwendung des Fernzugriffs über RDP [Benutzer]
SYS_2_2_3_A19 += 'SYS.2.2.3.A19 Verwendung des Fernzugriffs über RDP:\n';
result = 'erfüllt';

if( ! disabled_win_cmd_exec ){
  RDP_User = win_cmd_exec(cmd:'net localgroup "Remote Desktop Users"', password:passwd, username:usrname_WmiCmd);
  Administrators = win_cmd_exec(cmd:'net localgroup "Administrators"', password:passwd, username:usrname_WmiCmd);
}

if( ! RDP_User ){
  desc = 'Die Mitglieder der Gruppe "Remote Desktop Users" konnten nicht ausgelesen werden.';
  if( disabled_win_cmd_exec ){
    desc += " " + disabled_win_cmd_exec_report;
  }
  desc += '\n';
  result = 'error';
}else if( "is not recognized as an internal or external command" >< RDP_User ){
  desc = 'Die Mitglieder der Gruppe "Remote Desktop Users" konnten nicht ausgelesen werden.\n';
  result = 'error';
}else{
  desc = 'Folgende Benutzer sind Mitglieder der Gruppe "Remote Desktop Users":\n';
  RDP_User = split(RDP_User, keep:FALSE);
  foreach line (RDP_User){
    if( ereg(string:line, pattern:"^impacket", icase:TRUE) ){
      continue;
    }
    if( ereg(string:line, pattern:"^\[\*\]") ){
      continue;
    }
    desc += line + '\n';;
  }
  desc += '\n';
}

if( ! Administrators ){
  desc += 'Die Mitglieder der Gruppe "Administrators" konnten nicht ausgelesen werden.';
  if( disabled_win_cmd_exec ){
    desc += " " + disabled_win_cmd_exec_report;
  }
  desc += '\n';
  result = 'error';
}else if( "is not recognized as an internal or external command" >< Administrators ){
  desc += 'Die Mitglieder der Gruppe "Administrators" konnten nicht ausgelesen werden.\n';
  result = 'error';
}else{
  desc += 'Folgende Benutzer sind Mitglieder der Gruppe "Administrators" und haben somit einen Remote-Desktopzugriff:\n';
  Administrators = split(Administrators, keep:FALSE);
  foreach line (Administrators){
    if( ereg(string:line, pattern:"^impacket", icase:TRUE) ){
      continue;
    }
    if( ereg(string:line, pattern:"^\[\*\]") ){
      continue;
    }
    desc += line + '\n';
  }
}

DisableClipboard = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"fDisableClip");
DisablePrinters = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"fForceClientLptDef");
DisableLocalPrint = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"fDisableCpm");
DisableCOM = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"fDisableCcm");
DisableLPT = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"fDisableLPT");
DisableDrive = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"fDisableCdm");
DisableSmartCard = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"fEnableSmartCard");
DisablePlugAndPlay = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"fDisablePNPRedir");

if( DisableClipboard == "1" ){
  desc += 'Benutzer können die Zwischenablage nicht verwenden.\n';
}else{
  desc += 'Benutzer können die Zwischenablage verwenden.\n';
}

if( DisablePrinters == "1" ){
  desc += 'Der Standarddrucker des Remote-Hosts wird nicht als Drucker verwendet.\n';
}else{
  desc += 'Der Standarddrucker des Remote-Hosts wird als Drucker verwendet.\n';
}

if( DisableLocalPrint == "1" ){
  desc += 'Benutzer können keine Druckaufträge vom Remote-Host an einen lokalen Drucker senden.\n';
}else{
  desc += 'Benutzer können Druckaufträge vom Remote-Host an einen lokalen Drucker senden.\n';
}

if( DisableCOM == "1" ){
  desc += 'Benutzer können keine Daten an den lokalen COM-Port senden.\n';
}else{
  desc += 'Benutzer können Daten an den lokalen COM-Port senden.\n';
}

if( DisableLPT == "1" ){
  desc += 'Benutzer können keine Daten an den lokalen LPT-Port senden.\n';
}else{
  desc += 'Benutzer können Daten an den lokalen LPT-Port senden.\n';
}

if( DisableDrive == "1" ){
  desc += 'Laufwerke werden bei RDP-Sessions nicht eingebunden.\n';
  desc += 'Dateiablagen werden bei RDP-Session nicht unterstützt.\n';
}else{
  desc += 'Laufwerke werden bei RDP-Sessions eingebunden.\n';
  desc += 'Dateiablagen werden bei RDP-Session unterstützt.\n';
}

if( DisableSmartCard == "0" ){
  desc += 'Smartcard-Anschlüsse werden nicht eingebunden.\n';
}else{
  desc += 'Smartcard-Anschlüsse werden eingebunden.\n';
}

if( DisablePlugAndPlay == "1" ){
  desc += 'Unterstützte Plug-And-Play Geräte können in der RDP-Session nicht verwendet werden.\n';
}else{
  desc += 'Unterstützte Plug-And-Play Geräte können in der RDP-Session verwendet werden.\n';
}

SYS_2_2_3_A19 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.3.A19/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.3.A19/desc", value:desc);

# SYS.2.2.3.A20 Einsatz der Benutzerkontensteuerung für privilegierte Konten
SYS_2_2_3_A20 = 'SYS.2.2.3.A20 Einsatz der Benutzerkontensteuerung für privilegierte Konten:\n';
result = 'erfüllt';
if( get_kb_item("SMB/UAC") != 'success' ){
  desc = 'Die Registry konnte nicht ausgelesen werden.\n';
  result = 'error';
}else{
  EnableLUA = get_kb_item("SMB/UAC/EnableLUA");
  if( EnableLUA == '1' ){
    desc = 'UAC ist auf dem Host aktiviert.\n';
  }else{
    desc = 'UAC ist auf dem Host nicht aktiviert.\n';
    result = 'nicht erfüllt';
  }

  ConsentPromptBehaviorUser = get_kb_item("SMB/UAC/ConsentPromptBehaviorUser");
  if( ConsentPromptBehaviorUser == '0' ){
    desc += 'Anforderungen für erhöhte Rechte für Standardnutzer werden automatisch abgelehnt.\n';
  }else{
    desc += 'Anforderungen für erhöhte Rechte für Standardnutzer werden nicht automatisch abgelehnt.\n';
  }

  ConsentPromptBehaviorAdmin = get_kb_item("SMB/UAC/ConsentPromptBehaviorAdmin");
  if( ConsentPromptBehaviorAdmin == '0' ){
    desc += 'Administratoren erlangen erhöhte Rechte ohne Eingabeaufforderung.\n';
    result = 'nicht erfüllt';
  }else if( ConsentPromptBehaviorAdmin == '1' ){
    desc += 'Administratoren erlangen erhöhte Rechte nach Eingabeaufforderung zu Anmeldeinformationen auf einem sicheren Desktop.\n';
  }else if( ConsentPromptBehaviorAdmin == '2' ){
    desc += 'Administratoren erlangen erhöhte Rechte nach Eingabeaufforderung zur Zustimmung auf einem sicheren Desktop.\n';
  }else if( ConsentPromptBehaviorAdmin == '3' ){
    desc += 'Administratoren erlangen erhöhte Rechte nach Eingabeaufforderung zu Anmeldeinformationen.\n';
  }else if( ConsentPromptBehaviorAdmin == '4' ){
    desc += 'Administratoren erlangen erhöhte Rechte nach Eingabeaufforderung zur Zustimmung.\n';
  }else if( ConsentPromptBehaviorAdmin == '5' ){
    desc += 'Administratoren erlangen erhöhte Rechte nach Eingabeaufforderung zur Zustimmung für Nicht-Windows-Binärdateien.\n';
  }else{
    desc += 'Die Einstellung für das Verhalten der Eingabeaufforderung für erhöhte Rechte für Administratoren konnte nicht bestimmt werden.\n';
    result = 'error';
  }
}

SYS_2_2_3_A20 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.3.A20/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.3.A20/desc", value:desc);

# SYS.2.2.3.A21 Einsatz des Encrypting File Systems EFS (CI)
SYS_2_2_3_A21 += 'SYS.2.2.3.A21 Einsatz des Encrypting File Systems EFS (CI):\n';
EFSAlgorithmID = get_kb_item("WMI/WMI_EFSAlgorithmID");
result = 'erfüllt';
if( EFSAlgorithmID == "none" ){
  desc = 'EFS wird nicht verwendet.\n';
}else if( EFSAlgorithmID == '6610' ){
  desc = 'EFS wird mit einer AES 256-Bit Verschlüsselung verwendet.\n';
}else if( EFSAlgorithmID == '6603' ){
  desc = 'EFS wird mit einer 3DES Verschlüsselung verwendet.\n';
}else{
  desc = 'EFS wird verwendet. Die Art der Verschlüsselung konnte nicht ermittelt werden.\n';
  result = 'error';
}

if( LsaCfgFlags == "1" || LsaCfgFlags == "2" ){
  desc += 'Credential Guard ist aktiviert. Die Verschlüsselung der lokalen Passwortspeicher mittels Syskey kann daher entfallen.\n';
}else{
  desc += 'Credential Guard ist nicht aktiviert. Die Verschlüsselung der lokalen Passwortspeicher (z.B. mittels Syskey) muss manuell geprüft werden.\n';
  result = 'Diese Vorgabe muss manuell überprüft werden.';
}

SYS_2_2_3_A21 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.3.A21/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.3.A21/desc", value:desc);

# SYS.2.2.3.A22 Windows PowerShell (CIA)
SYS_2_2_3_A22 = 'SYS.2.2.3.A22 Windows PowerShell (CIA):\n';
WPS_Enabled = registry_get_dword(key:"Software\Policies\Microsoft\Windows\PowerShell", item:"EnableScripts");
ExecutionPolicy = registry_get_sz(key:"Software\Policies\Microsoft\Windows\PowerShell", item:"ExecutionPolicy");
EnableScriptBlockLogging = registry_get_dword(key:"Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", item:"EnableScriptBlockLogging");
EnableScriptBlockInvocationLogging = registry_get_dword(key:"Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", item:"EnableScriptBlockInvocationLogging");
result = 'erfüllt';

if( WPS_Enabled == "1" ){
  desc = 'Benutzer können die Windows PowerShell (WPS) als Option für ausführbare Programme auswählen.\n';
}else{
  desc = 'Windows PowerShell (WPS) ist deaktiviert. Es können keine WPS-Dateien ausgeführt werden.\n';
}

if( ExecutionPolicy == "AllSigned"){
  desc += 'Es dürfen nur signierte Scripts ausgeführt werden (ExecutionPolicy: AllSigned).\n';
}else{
  desc += 'Die Option "ExecutionPolicy: AllSigned" ist nicht gesetzt. ';
  desc += 'Dies sollte gesetzt werden, um sicherzustellen, dass nur signierte Scripte ausgeführt werden können.';
  result = 'nicht erfüllt';
}

if( EnableScriptBlockLogging == "1" ){
  desc += 'Die WPS-Ausführung wird protokolliert, unabhängig davon, ob diese interaktiv oder automatisch ausgeführt werden.\n';
}else{
  desc += 'Die WPS-Ausführung wird nicht protokolliert. Dies sollte aktiviert werden.\n';
  result = 'nicht erfüllt';
}

if( EnableScriptBlockInvocationLogging == "1" ){
  desc += 'Der Aufruf der WPS wird geloggt. Dies kann zu einer hohen Anzahl an Log-Events führen.\n';
}else{
  desc += 'Der Aufruf der WPS wird nicht geloggt.\n';
  result = 'nicht erfüllt';
}

SYS_2_2_3_A22 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.3.A22/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.3.A22/desc", value:desc);

# SYS.2.2.3.A23 Erweiterter Schutz der Anmeldeinformationen in Windows 10 (CI)
SYS_2_2_3_A23 = 'SYS.2.2.3.A23 Erweiterter Schutz der Anmeldeinformationen in Windows 10 (CI):\n';
SecureBoot = registry_get_dword(key:"System\CurrentControlSet\Control\SecureBoot\State", item:"UEFISecureBootEnabled");
result = 'erfüllt';
desc = '';
if( SecureBoot == "1" ){
  desc += 'SecureBoot ist aktiviert.\n';
  LSASS = registry_get_dword(key:"SYSTEM\CurrentControlSet\Control\Lsa", item:"RunAsPPL");
  if( LSASS == "1" ){
    desc += 'Der geschützte Modus für LSASS ist aktiviert. Der Status sollte bei Systemstart überwacht werden.\n';
  }else{
    desc += 'Der geschützte Modus für LSASS ist nicht aktiviert. Dieser sollte aktiviert und der Status bei Systemstart überwacht werden.\n';
    result = 'nicht erfüllt';
  }
}else{
  if( ! disabled_win_cmd_exec ){
    BootOption = win_cmd_exec(cmd:'type C:\\Windows\\Panther\\setupact.log|find /i "Detected boot environment"', password:passwd, username:usrname_WmiCmd);
    if( BootOption ){
      UEFI = ereg(string:BootOption, pattern:"Detected boot environment: (EFI|UEFI)", icase:TRUE, multiline:TRUE);
    }

    desc += 'SecureBoot ist deaktiviert.\n';
    if( UEFI ){
      desc += 'Der Host ist ein UEFI-basiertes System. Dementsprechend sollte SecureBoot aktiviert werden.\n';
      result = 'nicht erfüllt';
    }
  } else {
    desc = 'Es konnte nicht bestimmt werden ob es sich bei dem Host um ein UEFI-basiertes System handelt. ' + disabled_win_cmd_exec_report + '\n';
    result = 'error';
  }
}

RestrictedRemoteAdministration = registry_get_dword(key:"Software\Policies\Microsoft\Windows\CredentialsDelegation", item:"RestrictedRemoteAdministration");
RestrictedRemoteAdministrationType = registry_get_dword(key:"Software\Policies\Microsoft\Windows\CredentialsDelegation", item:"RestrictedRemoteAdministrationType");
if( RestrictedRemoteAdministration == "1" ){
  desc += 'Die Option "Restricted Admin" ist mit folgender Einstellung aktiviert:\n';
  if( RestrictedRemoteAdministrationType == "1" ){
    desc += '"Restricted Admin" muss verwendet werden, um eine RDP-Session herzustellen.\n';
  }else if( RestrictedRemoteAdministrationType == "2" ){
    desc += '"Remote Credential Guard" muss verwendet werden, um eine RDP-Session herzustellen.\n';
  }else if( RestrictedRemoteAdministrationType == "3" ){
    desc += '"Remote Credential Guard" oder "Restricted Admin" muss verwendet werden, um eine RDP-Session herzustellen.\n';
  }else{
    desc += 'Es konnte keine Spezifikation gefunden werden.\n';
    result = 'error';
  }
}else{
  desc += 'Die Option "Restricted Admin" ist nicht aktiviert. Ist eine Fernwartung per RDP vorgesehen, sollte diese aktiviert werden.\n';
  result = 'nicht erfüllt';
}

SYS_2_2_3_A23 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.3.A23/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.3.A23/desc", value:desc);

# SYS.2.2.3.A24 Aktivierung des Last-Access-Zeitstempels (A)
SYS_2_2_3_A24 = 'SYS.2.2.3.A24 Aktivierung des Last-Access-Zeitstempels (A):\n';
LastAccessTime = registry_get_dword(key:"SYSTEM\CurrentControlSet\Control\FileSystem", item:"NtfsDisableLastAccessUpdate");
if( LastAccessTime == "1" ){
  desc = 'Der Last-Access-Zeitstempel ist deaktiviert. Dieser sollte aktiviert werden.\n';
  result = 'nicht erfüllt';
}else{
  desc = 'Der Last-Access-Zeitstempel ist aktiviert.\n';
  result = 'erfüllt';
}

SYS_2_2_3_A24 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.3.A24/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.3.A24/desc", value:desc);

# SYS.2.2.3.A25Umgang mit Fernzugriffsfunktionen der "Connected User Experience and Telemetry" (CI)
SYS_2_2_3_A25 = 'SYS.2.2.3.A25 Umgang mit Fernzugriffsfunktionen der "Connected User Experience and Telemetry" (CI):\n';
result = 'erfüllt';
Telemetry = registry_get_dword(key:"Software\Policies\Microsoft\Windows\DataCollection", item:"AllowTelemetry");
if( Telemetry == "0" ){
  desc = 'Die Komponente "Telemetry" sendet minimale Daten an Microsoft. Die Einstellung entspricht der höchsten Sicherheitsstufe (GPO: Allow Telemetry, Wert: 0).\n';
}else{
  desc = 'Die Komponente "Telemetry" sendet Daten an Microsoft. Dies sollte auf die sicherste Stufe (GPO: Allow Telemetry, Wert: 0) gesetzt werden.\n';
  result = 'nicht erfüllt';
}

TelemetryProxyServer = registry_get_sz(key:"Software\Policies\Microsoft\Windows\DataCollection", item:"TelemetryProxyServer");
if( TelemetryProxyServer ){
  desc += 'Mittels der GPO "Configure Connected User Experiences and Telemetry" kann ein Proxyserver bestimmt werden, an den Anfragen für \n';
  desc += '"Connected User Experiences and Telemetry" gesendet werden sollen. Momentane Einstellung:\n' + TelemetryProxyServer + '\n';
}else{
  desc += 'Mittels der GPO "Configure Connected User Experiences and Telemetry" kann ein Proxyserver bestimmt werden, an den Anfragen für \n';
  desc += '"Connected User Experiences and Telemetry" gesendet werden sollen. Momentane ist dies nicht konfiguriert.\n';
  result = 'nicht erfüllt';
}

DisableEnterpriseAuthProxy = registry_get_dword(key:"Software\Policies\Microsoft\Windows\DataCollection", item:"DisableEnterpriseAuthProxy");
if( DisableEnterpriseAuthProxy == "1" ){
  desc += 'Die Komponente "Connected User Experiences and Telemetry" benutzt nicht automatisch einen authentifizierten Proxy um Daten an Microsoft zu senden.\n';
}else{
  desc += 'Die Komponente "Connected User Experiences and Telemetry" benutzt automatisch einen authentifizierten Proxy um Daten an Microsoft zu senden.\n';
  result = 'nicht erfüllt';
}

SYS_2_2_3_A25 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.3.A25/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.3.A25/desc", value:desc);

# Output
message += 'Basis-Absicherung:\n\n' + SYS_2_2_3_A1 + SYS_2_2_3_A2 + SYS_2_2_3_A3 + SYS_2_2_3_A4 + SYS_2_2_3_A5 + SYS_2_2_3_A6;
LEVEL = get_kb_item("GSHB/level");
if( LEVEL == 'Standard' || LEVEL == 'Kern'){
  message += '\n\nStandard-Absicherung:\n\n' + SYS_2_2_3_A7 + SYS_2_2_3_A8 + SYS_2_2_3_A9 + SYS_2_2_3_A10 + SYS_2_2_3_A11;
  message += SYS_2_2_3_A12 + SYS_2_2_3_A13 + SYS_2_2_3_A14 + SYS_2_2_3_A15 + SYS_2_2_3_A16 + SYS_2_2_3_A17;
  message += SYS_2_2_3_A18 + SYS_2_2_3_A19 + SYS_2_2_3_A20;
}
if( LEVEL == 'Kern' ){
  message += '\n\nKern-Absicherung:\n\n' + SYS_2_2_3_A21 + SYS_2_2_3_A22 + SYS_2_2_3_A23 + SYS_2_2_3_A24 + SYS_2_2_3_A25;
}

silence = get_kb_item("GSHB/silence");
if (!silence) log_message(port:0, data: message);

wmi_close(wmi_handle:handle);
exit(0);
