##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SYS.2.2.2.nasl 12387 2018-11-16 14:06:23Z cfischer $
#
# IT-Grundschutz Baustein: SYS.2.2.2 Clients unter Windows 8.1
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
  script_oid("1.3.6.1.4.1.25623.1.0.109037");
  script_version("$Revision: 12387 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 15:06:23 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-11-24 07:42:28 +0200 (Fri, 24 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('SYS.2.2.2 Clients unter Windows 8.1');
  script_xref(name:"URL", value:"https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_2_2_2_Clients_unter_Windows_8_1.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB-ITG");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_WMI_Antivir.nasl", "GSHB/GSHB_SMB_UAC_Config.nasl", "GSHB/GSHB_WMI_EFS.nasl");

  script_tag(name:"summary", value:"Zielsetzung dieses Bausteins ist der Schutz von Informationen,
  die durch und auf Windows 8.1-Clients verarbeiten werden.");

  exit(0);
}

include("host_details.inc");
include("wmi_user.inc");
include("smb_nt.inc");
include("misc_func.inc");
include("wmi_rsop.inc");

Windows_Version = get_kb_item("WMI/WMI_OSVER");
Windows_Name = get_kb_item("WMI/WMI_OSNAME");

if( Windows_Version != "6.3" || "windows 8.1" >!< tolower(Windows_Name) ){
  for( i=1; i<=21; i++){
    set_kb_item(name:"GSHB/SYS.2.2.2.A" + i + "/result", value:"nicht zutreffend");
    set_kb_item(name:"GSHB/SYS.2.2.2.A" + i + "/desc", value:"Auf dem Host ist kein Microsoft Windows 8.1 Betriebsystem installiert.");
  }
  log_message(data:"Auf dem Host ist kein Microsoft Windows 8.1 Betriebsystem installiert,
oder es konnte keine Verbindung zum Host hergestellt werden.");
  exit(0);
}

host    = get_host_ip();
usrname = kb_smb_login();
domain  = kb_smb_domain();
if( domain ){
  usrname = domain + '\\' + usrname;
}
passwd = kb_smb_password();

handle = wmi_connect(host:host, username:usrname, password:passwd, ns:'root\\rsop\\computer');
if( !handle ){
  for( i=1; i<=21; i++){
    set_kb_item(name:"GSHB/SYS.2.2.2.A" + i + "/result", value:"error");
    set_kb_item(name:"GSHB/SYS.2.2.2.A" + i + "/desc", value:"Es konnte keine Verbindung zum Host hergestellt werden (WMI connect failed).");
  }
  log_message(data:"Es konnte keine Verbindung zum Host hergestellt werden.");
  exit(0);
}


# SYS.2.2.2.A1 Geeignete Auswahl einer Windows 8.1-Version
SYS_2_2_2_A1 = 'SYS.2.2.2.A1 Geeignete Auswahl einer Windows 8.1-Version:\n';
Win_OSArchitecture = get_kb_item("WMI/WMI_OSArchitecture");
if( tolower(Win_OSArchitecture) =~ "64.*bit" ){
  desc = 'Auf dem Host wird eine 64-Bit Version von Windows 8.1 eingesetzt.\n';
  result = 'erfüllt';
}else{
  desc = 'Auf dem Host wird keine 64-Bit Version von Windows 8.1 eingesetzt.\n';
  desc += 'Aufgrund von erweiterten Sicherheitsfeatures sollte eine 64-Bit Version eingesetzt werden.\n';
  result = 'nicht erfüllt';
}

SYS_2_2_2_A1 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.2.A1/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.2.A1/desc", value:desc);

# SYS.2.2.2.A2 Festlegung eines Anmeldeverfahrens
SYS_2_2_2_A2 = 'SYS.2.2.2.A2 Festlegung eines Anmeldeverfahrens:\n';
reg_key = "SOFTWARE\Policies\Microsoft\Windows\System";
AllowPinLogon = registry_get_dword(key:reg_key, item:"AllowDomainPINLogon", type:"HKLM");
if( AllowPinLogon == 0 ){
  desc = 'Ein Login mit PIN ist auf dem Host nicht erlaubt.\n';
  result = 'erfüllt';
}else if( AllowPinLogon == 1 ){
  desc = 'Ein Login mit PIN ist auf dem Host erlaubt.\n';
  result = 'erfüllt';
}else{
  desc = 'Ein Login mit PIN wurde auf dem Host nicht konfiguriert.\n';
  desc += 'Ein User kann ein Login mit PIN (de-) aktivieren.\n';
  desc += 'Ein Login mit PIN sollte erlaubt oder verboten werden.\n';
  result = 'nicht erfüllt';
}

AllowPictureLogon = registry_get_dword(key:reg_key, item:"BlockDomainPicturePassword", type:"HKLM");
if( AllowPictureLogon == 1 ){
  desc += 'Ein Login mit Fotogeste ist auf dem Host nicht erlaubt.\n';
}else if( AllowPictureLogon == 0 ){
  desc += 'Ein Login mit Fotogeste ist auf dem Host erlaubt.\n';
}else{
  desc += 'Ein Login mit Fotogeste wurde auf dem Host nicht konfiguriert.\n';
  desc += 'Ein User kann ein Login mit Fotogeste aktivieren.\n';
  desc += 'Ein Login mit Fotogeste sollte erlaubt oder nicht erlaubt sein.\n';
  result = 'nicht erfüllt';
}

SYS_2_2_2_A2 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.2.A2/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.2.A2/desc", value:desc);


# SYS.2.2.2.A3 Einsatz von Viren-Schutzprogrammen
SYS_2_2_2_A3 = 'SYS.2.2.2.A3 Einsatz von Viren-Schutzprogrammen:\n';
SecurityCenter2 = get_kb_item("WMI/Antivir/SecurityCenter2");
SecurityCenter2 = split(SecurityCenter2, keep:FALSE);
if( max_index(SecurityCenter2) <= 1 ){
  desc = 'Es konnte kein Viren-Schutzprogramm im Security Center gefunden werden.\n';
  desc += 'Stellen Sie sicher, dass gleich- oder höherwertige Maßnahmen zum Schutz\n';
  desc += 'des IT-Sytems vor einer Infektion mit Schadsoftware getroffen wurden.\n';
  result = 'nicht erfüllt';
}else{
  desc = 'Folgende Schutzprogramme sind installiert:\n';
  result = 'erfüllt';

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

SYS_2_2_2_A3 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.2.A3/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.2.A3/desc", value:desc);

# SYS.2.2.2.A4 Beschaffung von Windows 8.1
SYS_2_2_2_A4 = 'SYS.2.2.2.A4 Beschaffung von Windows 8.1:\n';
SYS_2_2_2_A4 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.2.2.2.A5 Lokale Sicherheitsrichtlinien
SYS_2_2_2_A5 = 'SYS.2.2.2.A5 Lokale Sicherheitsrichtlinien:\n';
result = 'erfüllt';
AuditPolicy = wmi_rsop_auditpolicy(handle:handle, select:"Category");
if( AuditPolicy ){
  AuditPolicy = split(AuditPolicy, keep:FALSE);
  desc = 'Folgende Überwachungsrichtlinien sind auf dem Host aktiviert:\n';
  foreach line (AuditPolicy){
    line = split(line, sep:'|', keep:FALSE);

    if( tolower(line[0]) == 'category' ){
      continue;
    }

    desc += line[0] + '\n';
  }
  desc += '\n';
}else{
  desc ='Die Überwachungsrichtlinien konnten nicht ausgelesen werden.\n\n';
  result = 'error';
}

UserPrivilegeRight = wmi_rsop_userprivilegeright(handle:handle, select:"AccountList,UserRight");
if( UserPrivilegeRight ){
  UserPrivilegeRight = split(UserPrivilegeRight, keep:FALSE);
  desc += 'Folgende Benutzerrechte sind zugewiesen:\n';
  foreach line (UserPrivilegeRight){
    line = split(line, sep:'|', keep:FALSE);

    if( tolower(line[0]) == 'accountlist' ){
      continue;
    }

    desc += line[max_index(line)-1] + ' : ';

    for( y = 0; y <= max_index(line)-3; y++ ){
      desc += line[y];
      if( y == max_index(line)-3 ){
        desc += '\n';
      }else{
        desc += ', ';
      }
    }
  }

  desc += '\n';
}else{
  desc += 'Die zugewiesenen Benutzerrechte konnten nicht ausgelesen werden.\n';
  result = 'error';
}

desc += 'Hinweis: Es werden die Überwachungsrichtlinien und die Zuweisung von Benutzerrechten abgefragt.\n';

SYS_2_2_2_A5 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.2.A5/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.2.A5/desc", value:desc);

# SYS.2.2.2.A6 Datei- und Freigabeberechtigungen
SYS_2_2_2_A6 = 'SYS.2.2.2.A6 Datei- und Freigabeberechtigungen:\n';
SYS_2_2_2_A6 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.2.2.2.A7 Einsatz der Windows-Benutzerkontensteuerung UAC
SYS_2_2_2_A7 = 'SYS.2.2.2.A7 Einsatz der Windows-Benutzerkontensteuerung UAC:\n';
result = 'erfüllt';
if( get_kb_item("SMB/UAC") != 'success' ){
  desc = 'Fehler: Die Registry konnte nicht ausgelesen werden.\n';
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
    result = 'nicht erfüllt';
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

SYS_2_2_2_A7 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.2.A7/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.2.A7/desc", value:desc);

# SYS.2.2.2.A8 Verwendung der Heimnetzgruppen-Funktion [Benutzer]
SYS_2_2_2_A8 = 'SYS.2.2.2.A8 Verwendung der Heimnetzgruppen-Funktion:\n';
result = 'erfüllt';
FileAndPrint = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\FileAndPrint", item:"Enabled");
RemoteAddresses = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\FileAndPrint", item:"RemoteAddresses");
if( FileAndPrint == '0' ){
  desc = 'Die UDP-Ports 138, 139 und TCP-Pots 139, 445 werden blockiert. Datei- und Druckerfreigabe ist verhindert.\n';
  if( RemoteAddresses ){
    desc += 'Für IP-Adressen gelten Ausnahme-Regelungen:\n' + RemoteAddresses + '\n\n';
  }
}else{
  desc = 'Die UDP-Ports 138, 139 und TCP-Pots 139, 445 werden nicht blockiert. Datei- und Druckerfreigabe ist nicht verhindert.\n';
  result = 'nicht erfüllt';
}

HomeGroup = registry_get_dword(key:"Software\Policies\Microsoft\Windows\HomeGroup", item:"DisableHomeGroup");
if( HomeGroup == "1" ){
  desc += 'Benutzer können den Host nicht zu einer Heimnetzgruppe hinzufügen.\n';
}else{
  desc += 'Benutzer können den Host zu einer Heimnetzgruppe hinzufügen. Diese Einstellung sollte begründet sein.\n';
  result = 'nicht erfüllt';
}

SYS_2_2_2_A8 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.2.A8/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.2.A8/desc", value:desc);

# SYS.2.2.2.A9 Datenschutz und Datensparsamkeit bei Windows 8.1-Clients
SYS_2_2_2_A9 = 'SYS.2.2.2.A9 Datenschutz und Datensparsamkeit bei Windows 8.1-Clients:\n';
SYS_2_2_2_A9 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.2.2.2.A10 Integration von Online-Konten in das Betriebssystem
SYS_2_2_2_A10 = 'SYS.2.2.2.A10 Integration von Online-Konten in das Betriebssystem:\n';
result = 'erfüllt';
query = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeDenyInteractiveLogonRight' AND precedence=1";
SeDenyInteractiveLogonRight = wmi_query(wmi_handle:handle, query:query);
if( ! SeDenyInteractiveLogonRight ){
  desc = 'Es konnten keine Benutzer gefunden werden, denen die lokale Anmeldung verweigert wird (GPO "Lokale Anmeldung Verweigern").\n';
}else{
  SeDenyInteractiveLogonRight = split(SeDenyInteractiveLogonRight, keep:FALSE);
  desc = 'Folgenden Benutzern wird die lokale Anmeldung verweigert (GPO "Lokale Anmeldung Verweigern"):\n';
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
  desc += 'Es konnten keine Benutzer gefunden werden, denen die lokale Anmeldung zugelassen wird (GPO "Lokale Anmeldung Zulassen").\n\n';
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
        desc += '\n\n';
      }else{
        desc += ', ';
      }
    }
  }
}

SYS_2_2_2_A10 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.2.A10/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.2.A10/desc", value:desc);

# SYS.2.2.2.A11 Konfiguration von Synchronisationsmechanismen in Windows 8.1
SYS_2_2_2_A11 = 'SYS.2.2.2.A11 Konfiguration von Synchronisationsmechanismen in Windows 8.1:\n';
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
  desc += 'Dateien und Dokumente werden standardmäßig nicht auf OneDrive gespeichert.\n\n';
}else{
  desc += 'Dateien und Dokumente werden standardmäßig auf OneDrive gespeichert. ';
  desc += 'Dies sollte verhindert werden (GPO: "Dokumente standardmäßig auf OneDrive speichern")\n\n';
  result = 'nicht erfüllt';
}

SYS_2_2_2_A11 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.2.A11/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.2.A11/desc", value:desc);

# SYS.2.2.2.A12 Zentrale Authentifizierung in Windows-Netzwerken
SYS_2_2_2_A12 = 'SYS.2.2.2.A12 Zentrale Authentifizierung in Windows-Netzwerken:\n';
SYS_2_2_2_A12 += 'Diese Vorgabe muss manuelle überprüft werden.\n\n';

# SYS.2.2.2.A13 Anbindung von Windows 8.1 an AppStores
SYS_2_2_2_A13 = 'SYS.2.2.2.A13 Anbindung von Windows 8.1 an AppStores:\n';
result = 'erfüllt';
RemoveWindowsStore = registry_get_dword(key:"Software\Policies\Microsoft\WindowsStore", item:"RemoveWindowsStore");
if( RemoveWindowsStore == '1' ){
  desc = 'Windows Store ist deaktiviert.\n';
}else{
  desc = 'Windows Store ist nicht deaktiviert. Dieser sollte deaktiviert werden (GPO: "Windows Store deaktivieren")\n';
  result = 'nicht erfüllt';
}

AutoDownload = registry_get_dword(key:"Software\Policies\Microsoft\WindowsStore", item:"AutoDownload");
if( AutoDownload == '2' ){
  desc += 'Automatischer Download und Installation von Updates aus dem Windows Store ist deaktiviert.\n';
}else{
  desc += 'Automatischer Download und Installation von Updates aus dem Windows Store ist nicht deaktiviert.\n';
  desc += 'Dies sollten verhindert werden (GPO: "Automatischer Download und Installation von Updates abstellen")\n';
  result = 'nicht erfüllt';
}

SYS_2_2_2_A13 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.2.A13/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.2.A13/desc", value:desc);

# SYS.2.2.2.A14 Anwendungssteuerung mit Software Restriction Policies und AppLocker
SYS_2_2_2_A14 = 'SYS.2.2.2.A14 Anwendungssteuerung mit Software Restriction Policies und AppLocker (CIA):\n';
result = 'erfüllt';
key = "SOFTWARE\Policies\Microsoft\Windows\Safer";
if( registry_key_exists(key:key) ){
  desc = 'Software Restriction Policies (SRP) sind auf dem Host vorhanden. ';
  desc += 'Bitte prüfen Sie die Konfiguration der SRP.\n';
}else{
  desc = 'Software Restriction Policies (SRP) sind nicht auf dem Host vorhanden.\n';
  SRP = FALSE;
}

key = "Software\Policies\Microsoft\Windows\SrpV2";
if( registry_key_exists(key:key) ){
  desc += 'AppLocker ist auf dem Host vorhanden.\n';
  desc += 'Bitte prüfen Sie die Konfiguration von AppLocker.\n';
}else{
  desc += 'AppLocker ist nicht auf dem Host vorhanden.\n';
  AppLocker = FALSE;
}

if( SRP == FALSE && AppLocker == FALSE ){
  desc += 'Entweder SRP oder AppLocker sollte installiert und so konfiguriert sein,\n';
  desc += 'dass Anwendungen in Pfaden, die von Benutzern schreibbar sind, an der Ausführung\n';
  desc += 'gehindert werden.\n';
  result = 'nicht erfüllt';
}

SYS_2_2_2_A14 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.2.A14/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.2.A14/desc", value:desc);

# SYS.2.2.2.A15 Verschlüsselung des Dateisystems mit EFS
SYS_2_2_2_A15 = 'SYS.2.2.2.A15 Verschlüsselung des Dateisystems mit EFS (CI):\n';
result = 'erfüllt';
EncrFile = get_kb_item("WMI/WMI_EncrFile");
EncrDir = get_kb_item("WMI/WMI_EncrDir");
EFSAlgorithmID = get_kb_item("WMI/WMI_EFSAlgorithmID");

if( EFSAlgorithmID == "none" ){
  desc = 'EFS wird nicht verwendet.\n';
  result = 'nicht erfüllt';
}else if( EFSAlgorithmID == '6610' ){
  desc = 'EFS wird mit einer AES 256-Bit Verschlüsselung verwendet.\n';
}else if( EFSAlgorithmID == '6603' ){
  desc = 'EFS wird mit einer 3DES Verschlüsselung verwendet.\n';
}else{
  desc = 'EFS wird verwendet. Die Art der Verschlüsselung konnte nicht ermittelt werden.\n';
  result = 'error';
}

if( EncrFile == "none" ){
  desc += 'Es wurden keine verschlüsselten Dateien gefunden.\n';
  result = 'nicht erfüllt';
}else{
  desc += 'Folgende Dateien liegen verschlüsselt vor:\n' + EncrFile + '\n\n';
}

if( EncrDir == "none" ){
  desc += 'Es wurden keine verschlüsselten Odner gefunden.\n';
  result = 'nicht erfüllt';
}else{
  desc += 'Folgende Ordner liegen verschlüsselt vor:\n' + EncrFile + '\n\n';
}

SYS_2_2_2_A15 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.2.A15/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.2.A15/desc", value:desc);

# SYS.2.2.2.A16 Verwendung der Windows PowerShell
SYS_2_2_2_A16 = 'SYS.2.2.2.A16 Verwendung der Windows PowerShell (CIA):\n';
SYS_2_2_2_A16 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.2.2.2.A17 Sicherer Einsatz des Wartungscenters (CIA)
SYS_2_2_2_A17 += 'SYS.2.2.2.A17 Sicherer Einsatz des Wartungscenters (CIA):\n';
query = "select StartMode from Win32_Service WHERE Name='DPS' OR Name='WDiSvcHost' OR Name='WerSvc'";
StartModes = wmi_query(wmi_handle:handle, query:query);
if( StartModes ){
  StartModes = ereg_replace(string:StartModes, pattern:"\|", replace:' : ');
  desc = StartModes + '\n';
  result = 'Die Vorgabe muss manuell überprüft werden.';
}else{
  desc = 'Die Start-Einstellungen für die Windows 8-Dienste DPS, WDiSvcHost und WerSvc\n';
  desc += 'konnten nicht gelesen werden.\n';
  result = 'error';
}
desc += 'Bitte überprüfen Sie die Einstellungen des Wartungscenters und deaktivieren Sie die Einstellungen:\n';
desc += '"Neueste Problembehandlungen vom Windows-Onlinedienst für Problembehandlung abrufen", "Problemberichte senden",\n';
desc += '"Regelmäßig Daten über Computerkonfiguration an Microsoft senden", "Windows-Sicherung",\n';
desc += '"Programm zur Benutzerfreundlichkeit" und "Problembehandlung - andere Einstellungen"';

SYS_2_2_2_A17 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.2.A17/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.2.A17/desc", value:desc);

# SYS.2.2.2.A18 Aktivierung des Last-Access-Zeitstempels (A)
SYS_2_2_2_A18 = 'SYS.2.2.2.A18 Aktivierung des Last-Access-Zeitstempels (A):\n';
LastAccessTime = registry_get_dword(key:"SYSTEM\CurrentControlSet\Control\FileSystem", item:"NtfsDisableLastAccessUpdate");
if( LastAccessTime == "1" ){
  desc = 'Der Last-Access-Zeitstempel ist deaktiviert.\n';
  desc += 'Dies sollte begründet werden.\n';
  result = 'nicht erfüllt';
}else{
  desc = 'Der Last-Access-Zeitstempel ist aktiviert.\n';
  result = 'erfüllt';
}

SYS_2_2_2_A18 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.2.A18/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.2.A18/desc", value:desc);

# SYS.2.2.2.A19 Verwendung der Anmeldeinformationsverwaltung (C)
SYS_2_2_2_A19 = 'SYS.2.2.2.A19 Verwendung der Anmeldeinformationsverwaltung (C):\n';
result = 'Diese Vorgabe muss manuell überprüft werden.';
DisableTresor = registry_get_dword(key:"System\CurrentControlSet\Control\Lsa", item:"DisableDomainCreds");
if( DisableTresor == "1" ){
  desc = 'Zugangsdaten können nicht gespeichert werden (der sogenannte "Tresor" ist deaktiviert).\n\n';
}else{
  desc = 'Zugangsdaten können gespeichert werden (der sogenannte "Tresor" ist aktiviert).\n\n';
}

desc += 'Die Einstellung für den "Tresor" sollten in einer Richtlinie festgelegt sein.\n';
SYS_2_2_2_A19 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.2.A19/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.2.A19/desc", value:desc);

# SYS.2.2.2.A20 Sicherheit beim Fernzugriff über RDP (CIA)
SYS_2_2_2_A20 = 'SYS.2.2.2.A20 Sicherheit beim Fernzugriff über RDP (CIA):\n';
result = 'erfüllt';
RDPEnabled = registry_get_dword(key:"SYSTEM\CurrentControlSet\Control\Terminal Server", item:"fDenyTSConnection");
if( RDPEnabled == "1" ){;
  desc = 'RDP ist auf dem Host aktiviert.\n';
}else{
  desc = 'RDP ist auf dem Host deaktiviert.\n';
}

AlwaysPromptPassword = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"fPromptForPassword");
if( AlwaysPromptPassword == "1" ){
  desc += 'Bei der Verbindungsherstellung wird immer eine Kennworteingabe verlangt.\n';
}else{
  desc += 'Bei der Verbindungsherstellung wird nicht immer eine Kennworteingabe verlangt. Die Kennworteingabe sollte aktiviert werden.\n';
  result = 'nicht erfüllt';
}

NetworkLevelAuthentication = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"UserAuthentication");
if( NetworkLevelAuthentication == "1" ){
  desc += 'Benutzerauthentifizierung mit Authentifzierung auf Netzwerkebene ist für Remoteverbindungen erforderlich.\n';
}else{
  desc += 'Benutzerauthentifizierung mit Authentifzierung auf Netzwerkebene ist für';
  desc += 'Remoteverbindungen nicht erforderlich. Dies sollte aktiviert werden.\n';
  result = 'nicht erfüllt';
}

EncryptionLevel = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"MinEncryptionLevel");
if( EncryptionLevel == "3" ){
  desc += 'Die höchste Verschlüsselungsstufe wird verwendet (128 Bit).\n';
}else{
  desc += 'Die höchste Verschlüsselungsstufe wird nicht verwendet. Diese sollte verwendet werden (128 Bit Verschlüsselung).\n';
  result = 'nicht erfüllt';
}

OfferRemoteAssistance = registry_get_dword(key:"Software\policies\Microsoft\Windows NT\Terminal Services", item:"fAllowUnsolicited");
if( OfferRemoteAssistance == "0" ){
  desc += 'Remoteunterstützung anbieten ist deaktiviert.\n';
}else{
  desc += 'Remoteunterstützung anbieten ist nicht deaktiviert. Dies sollte deaktiviert sein.\n';
  result = 'nicht erfüllt';
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
  desc += 'Die maximale Gültigkeitsdauer der Einladung beträgt ' + MaxTicketExpiry + MaxTicketExpiryUnits;
}else{
  desc += 'Es ist keine maximale Gültigkeitsdauer der Einladung konfiguriert. Diese sollte eine angemessene Größe haben.\n';
  result = 'nicht erfüllt';
}

DisablePasswordSaving = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"DisablePasswordSaving");
if( DisablePasswordSaving == "1" ){
  desc += 'Benutzer dürfen keine Kennwörter speichern (automatische Kennwortanmeldung ist deaktiviert).\n';
}else{
  desc += 'Benutzer dürfen Kennwörter speichern. Die automatische Kennwortanmeldung sollte deaktiviert werden.\n';
  result = 'nicht erfüllt';
}

desc += 'Bitte prüfen Sie die Benutzerrechte der Gruppe der berechtigten Benutzer für dein Remote-Desktopzugriff manuell.\n';
desc += 'Eine Remote-Unterstützung sollte nur nach einer Einladung über EasyConnect oder auf Grundlage einer Einladungsdatei erfolgen.\n';

SYS_2_2_2_A20 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.2.2.A20/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.2.A20/desc", value:desc);

# SYS.2.2.2.A21 Einsatz von File und Registry Virtualization (CI)
SYS_2_2_2_A21 = 'SYS.2.2.2.A21 Einsatz von File und Registry Virtualization (CI):\n';
Virtualization = get_kb_item("SMB/UAC/EnableVirtualization");

if( Virtualization == "1" ){
  desc = 'File und Registry Virtualization sind aktiviert.\n';
  result = 'erfüllt';
}else{
  desc = 'File und Registry Virtualization sind deaktiviert.\n';
  result = 'nicht erfüllt';
}

SYS_2_2_2_A21 += desc;
set_kb_item(name:"GSHB/SYS.2.2.2.A21/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.2.A21/desc", value:desc);

# Output
message += 'Basis-Absicherung:\n\n' + SYS_2_2_2_A1 + SYS_2_2_2_A2 + SYS_2_2_2_A3;
LEVEL = get_kb_item("GSHB/level");
if( LEVEL == 'Standard' || LEVEL == 'Kern'){
  message += '\n\nStandard-Absicherung:\n\n' + SYS_2_2_2_A4 + SYS_2_2_2_A5 + SYS_2_2_2_A6 + SYS_2_2_2_A7;
  message += SYS_2_2_2_A8 + SYS_2_2_2_A9 + SYS_2_2_2_A10 + SYS_2_2_2_A11 + SYS_2_2_2_A12 + SYS_2_2_2_A13;
}
if( LEVEL == 'Kern' ){
  message += '\n\nKern-Absicherung:\n\n' + SYS_2_2_2_A14 + SYS_2_2_2_A15 + SYS_2_2_2_A16 + SYS_2_2_2_A17;
  message += SYS_2_2_2_A18 + SYS_2_2_2_A19 + SYS_2_2_2_A20 + SYS_2_2_2_A21;
}

silence = get_kb_item("GSHB/silence");
if (!silence) log_message(port:0, data: message);

wmi_close(wmi_handle:handle);
exit(0);
