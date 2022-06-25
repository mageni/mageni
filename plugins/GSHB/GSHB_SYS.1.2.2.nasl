##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SYS.1.2.2.nasl 12387 2018-11-16 14:06:23Z cfischer $
#
# IT-Grundschutz Baustein: SYS.1.2.2 Windows Server 2012
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
  script_oid("1.3.6.1.4.1.25623.1.0.109035");
  script_version("$Revision: 12387 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 15:06:23 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-11-15 14:42:28 +0200 (Wed, 15 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('SYS.1.2.2 Windows Server 2012');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB-ITG");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/EL15/GSHB_M4_097.nasl", "gb_ms_ie_detect.nasl");

  script_xref(name:"URL", value:"https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_1_2_2_Windows_Server_2012.html");

  script_tag(name:"summary", value:"Zielsetzung dieses Bausteins ist der Schutz von Informationen und Prozessen,
  die durch Serversysteme auf Basis von Windows Server 2012 (R2) im Regelbetrieb verarbeitet bzw. gesteuert werden.");

  exit(0);
}

include("host_details.inc");
include("wmi_user.inc");
include("smb_nt.inc");

Windows_OSName = get_kb_item("WMI/WMI_OSNAME");
if( "windows server 2012" >!< tolower(Windows_OSName) ){
  for( i=1; i<=14; i++){
    set_kb_item(name:"GSHB/SYS.1.2.2.A" + i + "/result", value:"nicht zutreffend");
    set_kb_item(name:"GSHB/SYS.1.2.2.A" + i + "/desc", value:"Auf dem Host ist kein Windows Server 2012 installiert.");
  }

  log_message(data:"Der Host ist kein Windows Server 2012 oder es konnte keine Verbindung zum Host hergestellt werden.");
  exit(0);
}

host    = get_host_ip();
usrname = kb_smb_login();
domain  = kb_smb_domain();
if( domain ){
  usrname = domain + '\\' + usrname;
}
passwd = kb_smb_password();

handle = wmi_connect(host:host, username:usrname, password:passwd);
if( !handle ){
  for( i=1; i<=14; i++){
    set_kb_item(name:"GSHB/SYS.1.2.2.A" + i + "/result", value:"error");
    set_kb_item(name:"GSHB/SYS.1.2.2.A" + i + "/desc", value:"Es konnte keine Verbindung zum Host hergestellt werden.");
  }
  wmi_close(wmi_handle:handle);
  log_message(data:"Es konnte keine Verbindung zum Host hergestellt werden.");
  exit(0);
}

# SYS.1.2.2.A1 Planung von Windows Server 2012
SYS_1_2_2_A1 = 'SYS.1.2.2.A1 Planung von Windows Server 2012:\n';
SYS_1_2_2_A1 = 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.1.2.2.A2 Sichere Installation von Windows Server 2012
SYS_1_2_2_A2 = 'SYS.1.2.2.A2 Sichere Installation von Windows Server 2012:\n';
query = "SELECT * FROM Win32_ServerFeature WHERE ID = '478' OR ID = '99'";
result = 'erfüllt';
res = wmi_query(wmi_handle:handle, query:query);
if( res ){
  desc = 'Die Server-Core-Variante ist nicht installiert. Dies muss begründet werden.\n';
  result = 'nicht erfüllt';
}else{
  desc = 'Die Server-Core-Variante ist installiert.\n';
}

SYS_1_2_2_A3 += desc + '\n';
set_kb_item(name:"GSHB/SYS.1.2.2.A3/result", value:result);
set_kb_item(name:"GSHB/SYS.1.2.2.A3/desc", value:desc);

# SYS.1.2.2.A3 Sichere Administration von Windows Server 2012
SYS_1_2_2_A3 = 'SYS.1.2.2.A3 Sichere Administration von Windows Server 2012:\n';
result = 'erfüllt';
query = "SELECT Name, PasswordChangeable, PasswordExpires, PasswordRequired, SID FROM Win32_UserAccount WHERE LocalAccount = 'True'";
res = wmi_query(wmi_handle:handle, query:query);
if( res == '' ){
  desc = 'Es konnte kein lokaler Account identifiziert werden.\n\n';
  result = 'erfüllt';
}else{
  res = split(res, keep:FALSE);
  foreach line (res){
    line = split(line, sep:"|", keep:FALSE);
    if( line[5] =~ 'S-1-5-21-[0-9,-]+-(500|512|544)$' ){
      if( tolower(line[4]) != 'true' ){
        InsecureLocalAccount += line[1] + '\n';
        result = 'nicht erfüllt';
      }
    }
  }

  if( result == 'nicht erfüllt'){
    desc = 'Folgende lokale Accounts benötigen kein Passwort zum Log-In:\n' + InsecureLocalAccount;
  }else{
    desc = 'Alle lokalen Accounts bedürfen eines Passworts zum Log-In. Bitte stellen Sie sicher,\n';
    desc += 'dass es sich hierbei um sichere Passwörter handelt.\n';
  }
}

SYS_1_2_2_A3 += desc + '\n';
set_kb_item(name:"GSHB/SYS.1.2.2.A3/result", value:result);
set_kb_item(name:"GSHB/SYS.1.2.2.A3/desc", value:desc);

# SYS.1.2.2.A4  Sichere Konfiguration von Windows Server 2012
SYS_1_2_2_A4 = 'SYS.1.2.2.A4 Sichere Konfiguration von Windows Server 2012:\n';
desc = get_kb_item("GSHB/M4_097/desc") + '\n';
result = get_kb_item("GSHB/M4_097/result");

Installed_IE = get_kb_item("MS/IE/Installed");
if( Installed_IE ){
  # Enhanced Security Configuration for Admins
  reg_key = "SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}";
  if( registry_key_exists(key:reg_key, type:"HKLM") ){
    ESC_Admins = registry_get_dword(key:reg_key, item:"IsInstalled", type:"HKLM");
  }

  if( ESC_Admins != '1' ){
    desc += 'Die Enhanced Security Configuration des Internet Explorers ist nicht für Administratoren aktiviert.\n';
    result = 'nicht erfüllt';
  }else{
    desc += 'Die Enhanced Security Configuration des Internet Explorers ist für Administratoren aktiviert.\n';
  }

  # Enhanced Security Configuration for Users
  reg_key = "SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}";
  if( registry_key_exists(key:reg_key, type:"HKLM") ){
    ESC_Users = registry_get_dword(key:reg_key, item:"IsInstalled", type:"HKLM" );
  }

  if( ESC_Users != '1' ){
    desc += 'Die Enhanced Security Configuration ist nicht für User aktiviert.\n';
    result = 'nicht erfüllt';
  }else{
    desc += 'Die Enhanced Security Configuration ist für User aktiviert.';
  }

  # Enhanced Protected Mode
  reg_key = "Software\Policies\Microsoft\Internet Explorer\Main";
  if( registry_key_exists(key:reg_key, type:"HKLM") ){
    EPM = registry_get_sz(key: reg_key, item:"Isolation", type:"HKLM");
  }

  if( EPM != 'PMEM' ){
    desc += 'Der Enhanced Protected Mode wird nicht genutzt.\n';
    result = 'nicht erfüllt';
  }else{
    desc += 'Der Enhanced Protected Mode wird genutzt.\n';
  }
}else{
  desc = 'Der Internet Explorer ist nicht installiert.\n';
}

SYS_1_2_2_A4 += desc + '\n';
set_kb_item(name:"GSHB/SYS.1.2.2.A4/result", value:result);
set_kb_item(name:"GSHB/SYS.1.2.2.A4/desc", value:desc);

# SYS.1.2.2.A5 Schutz vor Schadsoftware
SYS_1_2_2_A5 = 'SYS.1.2.2.A5 Schutz vor Schadsoftware:\n';
SYS_1_2_2_A5 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.1.2.2.A6 Sichere Authentisierung und Autorisierung in Windows Server 2012
SYS_1_2_2_A6 += 'SYS.1.2.2.A6 Sichere Authentisierung und Autorisierung in Windows Server 2012:\n';
result = 'erfüllt';

GROUPUSER = wmi_user_groupuser(handle:handle);
GROUPUSER = split(GROUPUSER, sep:'\n', keep:FALSE);
foreach USER (GROUPUSER) {
  USER = split(USER, sep:'|', keep:FALSE);
  if( "Win32_UserAccount" >< USER[1] ){
    Group = eregmatch(string:USER[0],pattern:'Name=".+"');
    if( "Administrator" >!< Group &&  "Guest" >!< Group && "Protected User" >!< Group ){
      Name = eregmatch(string:USER[1],pattern:'Name=".+"');
      Name = split(Name,sep:'"',keep:FALSE);
      NotValidUser += Name[1] + '\n';
    }
  }
  if( "Win32_SystemAccount" >< USER[1] ){
    Group = eregmatch(string:USER[0],pattern:'Name=".+"');
    if( "Protected User" >< Group ){
      Name = eregmatch(string:USER[1],pattern:'Name=".+"');
      Name = split(Name,sep:'"',keep:FALSE);
      SystemAccountWrongGroup += Name[1] + '\n';
    }
  }
}

reg_key = "SYSTEM\CurrentControlSet\Control\Lsa";
if( registry_key_exists(key:reg_key, type:"HKLM") ){
  PPL = registry_get_dword(key:reg_key, item:"RunAsPPL", type:"HKLM");
}

if( NotValidUser ){
  desc = 'Folgende Benutzer sind nicht Mitglied der Gruppen "Administrator", "Guest" oder "Protected User":\n' + NotValidUser + '\n';
  result = 'nicht erfüllt';
}else{
  desc = 'Es wurden keine Benutzer gefunden, die nicht Mitglied der Gruppen "Administrator", "Guest" oder "Protected User" sind.\n';
}

if( SystemAccountWrongGroup ){
  desc += 'Folgende System Accounts sind Mitglieder der Gruppe "Protected User":\n' + SystemAccountWrongGroup + '\n';
  result = 'nicht erfüllt';
}else{
  desc += 'Es wurde kein System Account in der Gruppe "Protected User" gefunden.\n';
}

if( PPL =="1" ){
  desc += 'Der zusätzliche LSA-Schutz wurde aktiviert.\n';
}else{
  desc += 'Der zusätzliche LSA-Schutz ist nicht aktiviert. Dies sollte aktiviert werden.';
  result = 'nicht erfüllt';
}

SYS_1_2_2_A6 += desc + '\n';
set_kb_item(name:"GSHB/SYS.1.2.2.A6/result", value:result);
set_kb_item(name:"GSHB/SYS.1.2.2.A6/desc", value:desc);

# SYS.1.2.2.A7 Sicherheitsprüfung von Windows Server 2012
SYS_1_2_2_A7 = 'SYS.1.2.2.A7 Sicherheitsprüfung von Windows Server 2012:\n';
SYS_1_2_2_A7 += 'Diese Maßnahme muss manuell überprüft werden.\n\n';

# SYS.1.2.2.A8 Schutz der Systemintegrität
SYS_1_2_2_A8 = 'SYS.1.2.2.A8 Schutz der Systemintegrität:\n';
result = 'erfüllt';
reg_key = "System\CurrentControlSet\Control\SecureBoot\State";
if( registry_key_exists(key:reg_key, type:"HKLM") ){
  SecureBoot = registry_get_dword(key:reg_key, item:"UEFISecureBootEnabled", type:"HKLM" );
}

if( SecureBoot == "1" ){
  desc = 'Secure Boot ist aktiv.\n';
}else{
  desc = 'Secure Boot ist nicht aktiv. Dies sollte aktiviert werden.\n';
  result = 'nicht erfüllt';
}

reg_key = "Software\Policies\Microsoft\Windows\SrpV2";
if( registry_key_exists(key:reg_key, type:"HKLM") ){
  desc += 'AppLocker ist aktiviert. Die Konfiguration muss manuell überprüft werden.\n';
}else{
  desc += 'AppLocker ist nicht aktiv. Dies sollte aktiviert werden.\n';
  result = 'nicht erfüllt';
}

SYS_1_2_2_A8 += desc + '\n';
set_kb_item(name:"GSHB/SYS.1.2.2.A8/result", value:result);
set_kb_item(name:"GSHB/SYS.1.2.2.A8/desc", value:desc);

# SYS.1.2.2.A9 Lokale Kommunikationsfilterung (CI)
SYS_1_2_2_A9 = 'SYS_1_2_2_A9 Lokale Kommunikationsfilterung (CI):\n';
Firewall_Private = "netsh advfirewall show private state";
Firewall_Public = "netsh advfirewall show public state";
Firewall_Domain = "netsh advfirewall show domain state";
result = 'erfüllt';

usrname = kb_smb_login();
domain = kb_smb_domain();
if ( domain ){
  usrname = domain + '/' + usrname;
}

disabled_win_cmd_exec = get_kb_item("win/lsc/disable_win_cmd_exec");
disabled_win_cmd_exec_report = "Die Verwendung der benoetigten win_cmd_exec Funktion wurde in 'Options for Local Security Checks (OID: 1.3.6.1.4.1.25623.1.0.100509)' manuell deaktiviert.";

if( ! disabled_win_cmd_exec ){
  Firewall_Private_Stat = win_cmd_exec(cmd:Firewall_Private, password:passwd, username:usrname);
  Firewall_Private_Stat = eregmatch(string:Firewall_Private_Stat, pattern:'State[ ]+(ON|OFF)');
  if( Firewall_Private_Stat[1] ){
    desc = 'Der Status des privaten Firewallprofils ist: ' + Firewall_Private_Stat[1] + '\n';
  }else{
    desc = 'Das private Firewallprofil konnte nicht ermittelt werden.\n';
    result = 'error';
  }

  Firewall_Public_Stat = win_cmd_exec(cmd:Firewall_Public, password:passwd, username:usrname);
  Firewall_Public_Stat = eregmatch(string:Firewall_Public_Stat, pattern:'State[ ]+(ON|OFF)');
  if( Firewall_Public_Stat[1] ){
    desc += 'Der Status des öffentlichen Firewallprofils ist: ' + Firewall_Public_Stat[1] + '\n';
  }else{
    desc += 'Das öffentliche Firewallprofil konnte nicht ermittelt werden.\n';
    result = 'error';
  }

  Firewall_Domain_Stat = win_cmd_exec(cmd:Firewall_Domain, password:passwd, username:usrname);
  Firewall_Domain_Stat = eregmatch(string:Firewall_Domain_Stat, pattern:'State[ ]+(ON|OFF)');
  if( Firewall_Domain_Stat[1] ){
    desc += 'Der Status des Firewallprofils "Domäne" ist: ' + Firewall_Domain_Stat[1] + '\n';
  }else{
    desc += 'Das domänen Firewallprofil konnte nicht ermittelt werden.\n';
    result = 'error';
  }
} else {
  desc = 'Das private Firewallprofil konnte nicht ermittelt werden.\n';
  desc += 'Das öffentliche Firewallprofil konnte nicht ermittelt werden.\n';
  desc += 'Das domänen Firewallprofil konnte nicht ermittelt werden.\n';
  desc += disabled_win_cmd_exec_report + '\n';
  result = 'error';
}

SYS_1_2_2_A9 += desc + '\n';
set_kb_item(name:"GSHB/SYS.1.2.2.A9/result", value:result);
set_kb_item(name:"GSHB/SYS.1.2.2.A9/desc", value:desc);

# SYS_1_2_2_A10 Festplattenverschlüsselung bei Windows Server 2012
SYS_1_2_2_A10 = 'SYS.1.2.2.A10 Festplattenverschlüsselung bei Windows Server 2012 (C):\n';
result = 'erfüllt';
desc = '';

if( ! disabled_win_cmd_exec ){
  cmd = "wmic logicaldisk get caption,drivetype";
  res = win_cmd_exec(cmd:cmd, password:passwd, username:usrname);
}

if( "not recognized" >< res || disabled_win_cmd_exec ){
  desc = "Der BitLocker status konnte nicht ermittelt werden. ";
  if( disabled_win_cmd_exec ) {
    desc += disabled_win_cmd_exec_report + '\n\n';
  } else {
    desc += '"wmic" wurde auf dem Host nicht erkannt.\n\n';
  }
  result = 'error';
}else{
  res = split(res, keep:FALSE);
  BitLockerInstalled = FALSE;
  foreach line (res){
    if( "3" >< line ){
      name = eregmatch(string:line,pattern:"[A-Z,a-z,0-9]+:");
      cmd = "manage-bde -status " + name[0];
      BitLocker = win_cmd_exec(cmd:cmd, password:passwd, username:usrname);
      if( "not recognized" >< BitLocker ){
        continue;
      }else{
        BitLockerInstalled = TRUE;
        BitLocker = split(BitLocker, keep:FALSE);
        foreach INFO (BitLocker){
          if( "protection status" >< tolower(INFO) ){
            if( "protection on" >!< tolower(INFO) ){
              desc += 'Der Datentäger: "' + name[0] + '" ist nicht mit BitLocker geschützt.\n';
              result = 'nicht erfüllt';
            }
          }
        }
      }
    }
  }
  if( ! BitLockerInstalled ){
    desc = 'BitLocker wird nicht verwendet.\n';
    result = 'nicht erfüllt';
  }
}

SYS_1_2_2_A10 += desc + '\n';
set_kb_item(name:"GSHB/SYS.1.2.2.A10/result", value:result);
set_kb_item(name:"GSHB/SYS.1.2.2.A10/desc", value:desc);

# SYS.1.2.2.A11 Angriffserkennung bei Windows Server 2012 (CIA)
SYS_1_2_2_A11 = 'SYS.1.2.2.A11 Angriffserkennung bei Windows Server 2012 (CIA):\n';
SYS_1_2_2_A11 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.1.2.2.A12 Redundanz und Hochverfügbarkeit (A)
SYS_1_2_2_A12 = 'SYS.1.2.2.A12 Redundanz und Hochverfügbarkeit (A):\n';
SYS_1_2_2_A12 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.1.2.2.A13 Starke Authentifizierung bei Windows Server 2012 (CI)
SYS_1_2_2_A13 = 'SYS.1.2.2.A13 Starke Authentifizierung bei Windows Server 2012 (CI):\n';
SYS_1_2_2_A13 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.1.2.2.A14 Herunterfahren verschlüsselter Server und virtueller Maschinen (CI)
SYS_1_2_2_A14 = 'SYS.1.2.2.A14 Herunterfahren verschlüsselter Server und virtueller Maschinen (CI):\n';
SYS_1_2_2_A14 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

message += 'Basis-Absicherung:\n\n' + SYS_1_2_2_A1 + SYS_1_2_2_A2 + SYS_1_2_2_A3;
LEVEL = get_kb_item("GSHB/level");
if( LEVEL == 'Standard' || LEVEL == 'Kern'){
  message += '\n\nStandard-Absicherung:\n\n' + SYS_1_2_2_A4 + SYS_1_2_2_A5 + SYS_1_2_2_A6 + SYS_1_2_2_A7 + SYS_1_2_2_A8;
}
if( LEVEL == 'Kern' ){
  message += '\n\nKern-Absicherung:\n\n' + SYS_1_2_2_A9 + SYS_1_2_2_A10 + SYS_1_2_2_A11 + SYS_1_2_2_A12 + SYS_1_2_2_A13 + SYS_1_2_2_A14;
}

silence = get_kb_item("GSHB/silence");
if (!silence) log_message(port:0, data: message);

wmi_close(wmi_handle:handle);
exit(0);
