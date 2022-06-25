##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SYS.1.3.nasl 12387 2018-11-16 14:06:23Z cfischer $
#
# IT-Grundschutz Baustein: SYS.1.3 Server unter Unix
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
  script_oid("1.3.6.1.4.1.25623.1.0.109036");
  script_version("$Revision: 12387 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 15:06:23 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-11-15 14:42:28 +0200 (Wed, 15 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('SYS.1.3 Server unter Unix');

  script_xref(name:"URL", value:"https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_1_3_Server_unter_Unix.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_dependencies("gather-package-list.nasl", "GSHB/GSHB_SSH_AppArmor_SeLinux.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB-ITG");

  script_tag(name:"summary", value:"Zielsetzung des Bausteins ist der Schutz von Informationen, die von Unix-Servern verarbeitet werden.");

  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");

Distribution = get_kb_item("ssh/login/release");
if( ! Distribution ){
  log_message(port:0, data:'Der Host ist kein Linux System. Maßnahme trifft nicht für das Zielsystem zu.\n');
  req = make_list("A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10",
      "A11", "A12", "A13", "A14", "A15", "A16", "A17");
  foreach r (req){
    set_kb_item(name:"GSHB/SYS.1.3." + r + "/result", value:"nicht zutreffend");
    set_kb_item(name:"GSHB/SYS.1.3." + r + "/desc", value:"Auf dem Host ist kein Linux installiert.");
  }
  exit(0);
}

port = kb_ssh_transport();
host_ip = get_host_ip();

sock = ssh_login_or_reuse_connection();
if( !sock ) {
  error = get_ssh_error();
  if( !error )
    error = "No SSH Port or Connection!";
    log_message(port:port, data:error);
    exit(0);
}


debian_version = get_kb_item("ssh/login/release");

# SYS.1.3.A1 Benutzerauthentisierung unter Unix
SYS_1_3_A1 = 'SYS.1.3.A1 Benutzerauthentisierung unter Unix:\n';
SYS_1_3_A1 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.1.3.A2 Sorgfältige Vergabe von IDs
SYS_1_3_A2 = 'SYS.1.3.A2 Sorgfältige Vergabe von IDs:\n';
res = 'erfüllt';
cmd = 'getent passwd | cut -f1 -d: | uniq -c -d';
Logins = ssh_cmd(socket:sock, cmd:cmd);
if( "command not found" >< tolower(Logins) ){
  desc = 'Der Befehl "getent", "uniq" oder "cut" ist dem System nicht bekannt. Diese Vorgabe kann nicht überprüft werden.\n';
  res = 'error';
}else if( "permission denied" >< tolower(Logins) ){
  desc = 'Die Datei /etc/passwd konnte nicht gelesen werden (Keine Berechtigung).\n';
  res = 'error';
}else{
  if( Logins ){
    desc = 'Folgende Login-Namen sind mehrfach in der Datei /etc/passwd enthalten:\n' + Logins + '\n\n';
    res = 'nicht erfüllt';
  }else{
    desc = 'Es wurden keine mehrfachen Login-Namen in der Datei /etc/passwd gefunden.\n';
  }

  cmd = 'getent passwd | cut -f3 -d: | uniq -d';
  Mult_UIDs = ssh_cmd(socket:sock, cmd:cmd);
  if( Mult_UIDs ){
    desc += 'Folgende UIDs sind mehrfach in der Datei /etc/passwd enthalten:\n' + Logins + '\n\n';
    res = 'nicht erfüllt';
  }else{
    desc += 'Es wurden keine mehrfachen UIDs in der Datei /etc/passwd gefunden.\n';
  }

  cmd = 'getent group | cut -d: -f3 | uniq -c -d';
  Mult_GIDs = ssh_cmd(socket:sock, cmd:cmd);
  if( Mult_GIDs ){
    desc += 'Folgende GIDs sind mehrfach in der Datei /etc/group enthalten:\n' + Logins + '\n\n';
    res = 'nicht erfüllt';
  }else{
    desc += 'Es wurden keine mehrfachen GIDs in der Datei /etc/group gefunden.\n';
  }
}

cmd = 'cat /etc/group | cut -d : -f 3';
Group = ssh_cmd(socket:sock, cmd:cmd);
if( "permission denied" >< tolower(Group) || ! Group ){
  desc += 'Die Datei "/etc/groups" konnte nicht gelesen werden.\n';
  res = 'error';
}else{
  GIDs = split(Group, keep:FALSE);

  cmd = 'cat /etc/passwd';
  Users = ssh_cmd(socket:sock, cmd:cmd);
  if( "permission denied" >< tolower(Users) || ! Users ){
    res = 'error';
  }else{
    Users = split(Users, keep:FALSE);
    foreach User (Users) {
      User = split(User, sep:':', keep:FALSE);
      if( ! in_array(search:User[3], array:GIDs) ){
        NoGID += User[0] + ' : ' + User[3] + '\n';
      }
    }
  }
  if( NoGID ){
    desc += 'Folgende Benutzer besitzen eine GID, welche nicht in der Datei /etc/group vorhanden ist (User:GID):\n' + NoGID + '\n';
    res = 'nicht erfüllt';
  }else{
    desc += 'Es wurden keine Benutzer mit einer ungueltigen GID gefunden.\n';
  }
}

desc += 'Bitte überprüfen Sie manuell, dass Gruppen nur die unbedingt notwendigen
Benutzer enthalten.\n';
SYS_1_3_A2 += desc + '\n';

set_kb_item(name:"GSHB/SYS.1.3.A2/result", value:res);
set_kb_item(name:"GSHB/SYS.1.3.A2/desc", value:desc);

# SYS.1.3.A3 Automatisches Einbinden von Wechsellaufwerken
SYS_1_3_A3 = 'SYS.1.3.A3  Automatisches Einbinden von Wechsellaufwerken:\n';
res = 'erfüllt';
cmd = 'dpkg -s autofs';
Autofs = ssh_cmd(socket:sock, cmd:cmd);
if( "install ok installed" >< tolower(Autofs) ){
  desc = 'Das Paket "autofs" ist auf dem Host vorhanden.
Dies kann automatisches Einbinden von Wechsellaufwerken zur Folge haben und sollte
daher entfernt werden.\n';
  res = 'nicht erfüllt';
}else if( ! Autofs ){
  desc = 'Es konnte nicht ermittelt werden, ob das Paket "autofs" auf dem Host vorhanden ist.\n';
  res = 'error';
}else{
  desc = 'Das Paket "autofs", welches Laufwerke automatisch einbindet, ist nicht auf dem Host installiert.\n';
}

cmd = 'dpkg -s usbmount';
USBmount = ssh_cmd(socket:sock, cmd:cmd);
if( "install ok installed" >< tolower(USBmount) ){
  desc += 'Das Paket "usbmount" ist auf dem Host vorhanden.
Dies kann automatisches Einbinden von USB-Laufwerken zur Folge haben und sollte
daher entfernt werden.\n\n';
  res = 'nicht erfüllt';
}else if( ! USBmount ){
  desc += 'Es konnte nicht ermittelt werden, ob das Paket "usbmount" auf dem Host vorhanden ist.\n';
  res = 'error';
}else{
  desc += 'Das Paket "usbmount", welches USB-Laufwerke automatisch einbindet, ist nicht auf dem Host installiert.\n';
}

SYS_1_3_A3 += desc + '\n';
set_kb_item(name:"GSHB/SYS.1.3.A3/result", value:res);
set_kb_item(name:"GSHB/SYS.1.3.A3/desc", value:desc);


# SYS.1.3.A4 Schutz von Anwendungen
SYS_1_3_A4 = 'SYS.1.3.A4  Schutz von Anwendungen:\n';
res = 'erfüllt';
cmd = 'cat /proc/sys/kernel/randomize_va_space';
ASLR = ssh_cmd(socket:sock, cmd:cmd);
if( ASLR == '2' ){
  desc = 'ASLR ist aktiviert (randomize_va_space = 2)\n';
}else if( ASLR == '1' ){
  desc = 'ASLR ist aktiviert (randomize_va_space = 1). Es sollte überlegt werden, dies auf "2" zu setzen.\n';
}else{
  desc = 'ASLR ist nicht aktiviert.\n';
  res = 'nicht erfüllt';
}

cmd = 'dmesg | grep NX | grep protection';
DEPNX = ssh_cmd(socket:sock, cmd:cmd);
if( ! DEPNX ){
  cmd = 'cat /var/log/messages | grep NX | grep protection';
  var_messages_DEPNX = ssh_cmd(socket:sock, cmd:cmd);
  if( "permission denied" >< tolower(var_messages_DEPNX) ){
    desc += 'Die Datei /var/log/messages konnte nicht gelesen werden.\n';
    res = 'error';
  }else{
    if( 'active' >< tolower(DEPNX) ){
      desc += 'DEP/NX ist aktiviert.\n';
    }else{
      desc += 'DEP/NX ist nicht aktiviert.\n';
      res = 'nicht erfüllt';
    }
  }
}else if( 'active' >< tolower(DEPNX) ){
  desc += 'DEP/NX ist aktiviert.\n';
}else{
  desc += 'DEP/NX ist nicht aktiviert.\n';
  res = 'nicht erfüllt';
}

desc += 'Bitte überprüfen Sie manuell, ob Sicherheitsfunktionen und Standardbibliotheken
des Kernels nicht deaktiviert sind.\n';

SYS_1_3_A4 += desc + '\n';
set_kb_item(name:"GSHB/SYS.1.3.A4/result", value:res);
set_kb_item(name:"GSHB/SYS.1.3.A4/desc", value:desc);


# SYS.1.3.A5 Sichere Installation von Software-Paketen
SYS_1_3_A5 = 'SYS.1.3.A5 Sichere Installation von Software-Paketen:\n';
SYS_1_3_A5 += 'Diese Vorgabe muss manuell überprüft werden werden.\n\n';


# SYS.1.3.A6 Verwaltung von Benutzern und Gruppen
SYS_1_3_A6 = 'SYS.1.3.A6 Verwaltung von Benutzern und Gruppen:\n';
res = 'erfüllt';
cmd = 'ls -l /etc/passwd';
passwd_access = ssh_cmd(socket:sock, cmd:cmd);
passwd_access_correct = ereg(string:passwd_access, pattern:'-rw-r--r--.+root');
cmd = 'ls -l /etc/group';
group_access = ssh_cmd(socket:sock, cmd:cmd);
group_access_correct = ereg(string:group_access, pattern:'-rw-r--r--.+root');
cmd = 'ls -l /etc/sudoers';
sudoers_access = ssh_cmd(socket:sock, cmd:cmd);
sudoers_access_correct = ereg(string:sudoers_access, pattern:'-r--r-----.+root');

if( passwd_access_correct == '1' ){
  desc = 'Der Besitzer der Datei "/etc/passwd" ist "root". Andere Benutzer besitzen lediglich Leserechte.\n';
}else{
  desc = 'Entweder ist "root" nicht der Besitzer der Datei "/etc/passwd" und / oder die Zugriffsrechte sind nicht richtig vergeben.
Es sollten folgende Rechte gelten: -rw-r--r--\n';
  res = 'nicht erfüllt';
}
if( group_access_correct == '1' ){
  desc += 'Der Besitzer der Datei "/etc/group" ist "root". Andere Benutzer besitzen lediglich Leserechte.\n';
}else{
  desc += 'Entweder ist "root" nicht der Besitzer der Datei "/etc/group" und / oder die Zugriffsrechte sind nicht richtig vergeben.
Es sollten folgende Rechte gelten: -rw-r--r--\n';
  res = 'nicht erfüllt';
}
if( sudoers_access_correct == '1' ){
  desc += 'Der Besitzer der Datei "/etc/sudoers" ist "root". Nur dieser besitzt Leserechte.\n';
}else{
  desc += 'Entweder ist "root" nicht der Besitzer der Datei "/etc/sudoers" und / oder die Zugriffsrechte sind nicht richtig vergeben.
Es sollten folgende Rechte gelten: -r--r-----\n';
  res = 'nicht erfüllt';
}

SYS_1_3_A6 += desc + '\n';
set_kb_item(name:"GSHB/SYS.1.3.A6/result", value:res);
set_kb_item(name:"GSHB/SYS.1.3.A6/desc", value:desc);


# SYS.1.3.A7 Zusaetzliche Absicherung des Zugangs zum Single-User- und Wiederherstellungsmodus
SYS_1_3_A7 = 'SYS.1.3.A7 Zusätzliche Absicherung des Zugangs zum Single-User- und Wiederherstellungsmodus:\n';
SYS_1_3_A7 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.1.3.A8 Verschluesselter Zugriff über Secure Shell
SYS_1_3_A8 = 'SYS.1.3.A8 Verschlüsselter Zugriff über Secure Shell:\n';
res = 'erfüllt';
cmd = 'dpkg -s telnet';
telnet = ssh_cmd(socket:sock, cmd:cmd);
if( "status: install ok installed" >< tolower(telnet) ){
  desc = 'Das Paket "telnet" ist auf dem Host installiert. Dies sollte deinstalliert werden.\n';
  res = 'nicht erfüllt';
}else{
  desc += 'Das Paket "telnet" ist nicht auf dem Host installiert.\n';
}

cmd = 'dpkg -s telnetd';
telnet = ssh_cmd(socket:sock, cmd:cmd);
if( "status: install ok installed" >< tolower(telnet) ){
  desc += 'Das Paket "telnetd" ist auf dem Host installiert. Dies sollte deinstalliert werden.\n';
  res = 'nicht erfüllt';
}else{
  desc += 'Das Paket "telnetd" ist nicht auf dem Host installiert.\n';
}

SYS_1_3_A8 += desc + '\n';
set_kb_item(name:"GSHB/SYS.1.3.A8/result", value:res);
set_kb_item(name:"GSHB/SYS.1.3.A8/desc", value:desc);

# SYS.1.3.A9 Absicherung des Bootvorgangs
SYS_1_3_A9 = 'SYS.1.3.A9 Absicherung des Bootvorgangs:\n';
SYS_1_3_A9 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';


# SYS.1.3.A10 Verhinderung der Ausbreitung bei der Ausnutzung von Schwachstellen
SYS_1_3_A10 = 'SYS.1.3.A10 Verhinderung der Ausbreitung bei der Ausnutzung von Schwachstellen:\n';
res = 'nicht erfüllt';
AppArmor_Basic = get_kb_item("GSHB/AppArmor_Basic");
AppArmor_Utils = get_kb_item("GSHB/AppArmor_Utils");
if( AppArmor_Basic == '1' ) {
  desc = 'Das Paket "apparmor" ist auf dem Host installiert.\n';
  res = 'erfüllt';
  if( AppArmor_Utils != '1' ){
    desc += 'Das Paket "apparmor-utils" ist nicht auf dem Host installiert.
  für eine weitere Analyse von AppArmor muss dieses Paket installiert sein.\n';
  }else{
    AppArmor_Status = get_kb_item("GSHB/AppArmor_Status");
    if( AppArmor_Status == "error" || ! AppArmor_Status){
      desc += 'AppArmor scheint installiert zu sein. Der Befehl "aa-status" ist jedoch nicht bekannt.
  Dies kann an fehlenden Berechtigungen liegen.\n';
    }else{
      desc += 'AppArmor ist in folgendem Zustand:\n' + AppArmor_Status + '\n';
    }
  }
}else{
  desc = 'Das Paket "apparmor" ist nicht auf dem Host installiert.\n';
}


SELinux_Basics = get_kb_item("GSHB/SeLinux_Basics");
SELinux_Utils = get_kb_item("GSHB/SeLinux_Utils");
if( SELinux_Basics == '1' ){
  desc += 'Das Paket "selinux-bascis" ist auf dem Host installiert.\n';
  res = 'erfüllt';
  if( SELinux_Utils != '1' ){
    desc += 'Das Paket "selinux-utils" ist auf dem Host nicht installiert.
  für eine weitere Analyse von SELinux muss dieses Paket installiert sein.\n';
    res = 'error';
  }else{
    desc += 'Das Paket "selinux-utils" ist auf dem Host installiert.\n';
    sestatus = get_kb_item("GSHB/SeLinux_Status");
    if( ! sestatus || sestatus == "error" ){
      desc += 'Der Befehl "sestatus" ist dem System nicht bekannt.
  Es koennen keine Informationen über SELinux gefunden werden.\n';
    }else{
      desc += 'SELinux ist in folgendem Zustand:\n' + sestatus + '\n';
    }
  }
}else{
  desc += 'Das Paket "selinux-basics" ist nicht auf dem Host installiert.\n';
}


if( res == 'nicht erfüllt' ){
 desc += ' Weder "AppArmor" noch "SeLinux" wurde auf dem System erkannt.
Bitte überprüfen Sie manuell, ob Dienste und Anwendungen anderweitig abgesichert werden.\n';
}

SYS_1_3_A10 += desc + '\n';
set_kb_item(name:"GSHB/SYS.1.3.A10/result", value:res);
set_kb_item(name:"GSHB/SYS.1.3.A10/desc", value:desc);

# SYS.1.3.A11 Einsatz der Sicherheitsmechanismen von NFS
SYS_1_3_A11 = 'SYS.1.3.A11 Einsatz der Sicherheitsmechanismen von NFS:\n';
res = 'Diese Vorgabe muss manuell überprüfen werden.';
cmd = 'dpkg -s nfs-common nfs-kernel-server';
NFS_ = ssh_cmd(socket:sock, cmd:cmd);
NFS_Common = ereg(string:NFS_, pattern:'Package: nfs-common\nStatus: install ok installed', multiline:TRUE);
NFS_Kernel_Server = ereg(string:NFS_, pattern:'Package: nfs-kernel-server\nStatus: install ok installed', multiline:TRUE);
if( NFS_Common != '1' ){
  desc = 'Das Paket "nfs-common" ist nicht auf dem Host installiert.\n';
  res = 'nicht zutreffend';
}else{
  desc = 'Das Paket "nfs-common" ist auf dem Host installiert.\n';
}
if( NFS_Kernel_Server != '1' ){
  desc += 'Das Paket "nfs-kernel-server" ist nicht auf dem Host installiert.
Es scheint sich nicht um einen NFS-Server zu handeln.\n';
  res = 'nicht zutreffend';
}else{
  desc += 'Das Paket "nfs-kernel-server" ist auf dem Host installiert.\n';
}

if( res != 'nicht zutreffend' ){
  desc += 'Aufgrund der installierten Pakete wird davon ausgegangen, dass es sich
um einen NFS-Server handelt. Bitte überprüfen Sie manuell, ob nur unbedingt notwendige
Verzeichnisse exportiert werden und die mountbaren Verzeichnisse auf das notwendige Maß
reduziert werden\n.';
}

SYS_1_3_A11 += desc + '\n';
set_kb_item(name:"GSHB/SYS.1.3.A11/result", value:res);
set_kb_item(name:"GSHB/SYS.1.3.A11/desc", value:desc);

# SYS.1.3.A12 Einsatz der Sicherheitsmechanismen von NIS
SYS_1_3_A12 = 'SYS.1.3.A12 Einsatz der Sicherheitsmechanismen von NIS:\n';
res = 'erfüllt';
cmd = 'dpkg -s nis';
NIS = ssh_cmd(socket:sock, cmd:cmd);
if( "'nis' is not installed" >< NIS ){
  desc = 'Das Paket "nis" ist nicht auf dem Host installiert.\n';
  desc += 'Es wird davon ausgegangen, dass es sich bei dem Host nicht um ein NIS Server handelt.\n';
  res = 'nicht zutreffend';
}else{
  cmd = 'cat /etc/passwd | grep "+::0:0:::"';
  passwd = ssh_cmd(socket:sock, cmd:cmd);
  if( passwd ){
    desc = 'In der Datei "/etc/passwd" wurde der Eintrag "+::0:0:::" gefunden. Dieser sollte entfernt werden.\n';
    res = 'nicht erfüllt';
  }else{
    desc = 'Der Eintrag "+::0:0:::" wurde nicht in der Datei "/etc/passwd" gefunden.\n';
  }

  cmd = 'cat /etc/group | grep "+::0:0:::"';
  group = ssh_cmd(socket:sock, cmd:cmd);
  if( group ){
    desc += 'In der Datei "/etc/group" wurde der Eintrag "+::0:0:::" gefunden. Dieser sollte entfernt werden.\n';
    res = 'nicht erfüllt';
  }else{
    desc += 'Der Eintrag "+::0:0:::" wurde nicht in der Datei "/etc/group" gefunden.\n';
  }

  cmd = 'cat /var/yp/securenets';
  YPSERV = ssh_cmd(socket:sock, cmd:cmd);
  if( "no such file or directory" >< tolower(YPSERV) || ! YPSERV ){
    desc += 'Die Datei "/var/yp/securenets" konnte nicht gefunden werden.\n';
    desc += 'Diese sollte konfiguriert werden, damit nur Anfragen von festgelegten Rechnern beantwortet werden.\n\n';
    res = 'nicht erfüllt';
  }else{
    desc += 'Auf dem Server existiert die Datei "/var/yp/securenets". Die legt die
Rechner fest, von denen der Server-Prozess "ypserv" Anfragen beantwortet. Die Einträge
müssen manuell überprüft werden.\n';
  }
}

SYS_1_3_A12 += desc + '\n';
set_kb_item(name:"GSHB/SYS.1.3.A12/result", value:res);
set_kb_item(name:"GSHB/SYS.1.3.A12/desc", value:desc);


# SYS.1.3.A13 Zusaetzlicher Schutz der priviligierten Anmeldeinformationen (CI)
SYS_1_3_A13 = 'SYS.1.3.A13 Zusätzlicher Schutz der priviligierten Anmeldeinformationen (CI):\n';
res = 'erfüllt';
cmd = "cat /etc/ssh/sshd_config | grep -v '^#' | grep -v -e '^$'";
AdminLock = ssh_cmd(socket:sock, cmd:cmd);
if( "permission denied" >< tolower(AdminLock) || ! AdminLock ){
  desc = 'Die Datei "/etc/ssh/sshd_config" konnte nicht gelesen werden.\n';
  res = 'error';
}else{
  pattern = 'PermitRootLogin [a-z,A-Z,-]+';
  PermitRootLogin=eregmatch(string:AdminLock, pattern:pattern, multiline:TRUE);
  if( ! PermitRootLogin ){
    desc = 'Der Eintrag "PermitRootLogin" in "/etc/ssh/sshd_config" sollte auf "no"
gesetzt sein, um eine Anmeldung von root über SSH am System zu verhindern.\n';
    res = 'nicht erfüllt';
  }else{
    PermitRootLogin=split(PermitRootLogin[0], sep:' ',keep:FALSE);
    if( PermitRootLogin[1] == 'no' ){
      desc = 'Der Eintrag "PermitRootLogin" in der Datei "/etc/ssh/sshd_config" ist auf den Wert "no" gesetzt.\n';
      desc += '"root" kann sich nicht direkt am System über SSH anmelden\n';
    }else{
    desc = 'Der Eintrag "PermitRootLogin" in "/etc/ssh/sshd_config" sollte auf "no"
gesetzt sein, um eine Anmeldung von root über SSH am System zu verhindern.\n';
    res = 'nicht erfüllt';
    }
  }
  pattern = 'MaxAuthTries [0-9]+';
  MaxAuthTries=eregmatch(string:AdminLock, pattern:pattern, multiline:TRUE);
  if( ! MaxAuthTries ){
    desc += 'Der Eintrag "MaxAuthTries" in "/etc/ssh/sshd_config" sollte auf einen
angemessenen Wert gesetzt sein, um Brute-Force-Angriffe über SSH am System zu verhindern.\n';
    res = 'nicht erfüllt';
  }else{
    MaxAuthTries=split(MaxAuthTries[0], sep:' ',keep:FALSE);
    if( MaxAuthTries[1] > '0' && MaxAuthTries [1] <= '5' ){
      desc += 'Benutzer haben ' + MaxAuthTries[1] + ' Anmeldeversuche, bevor das Konto
gesperrt wird.\n';
    }
  }
}

SYS_1_3_A13 += desc + 'Es sollte manuell geprueft werden, ob das Vier-Augen-Prinzip angewandt wird
oder die Authentisierung mittels SmartCards erfolgen kann.\n\n';
set_kb_item(name:"GSHB/SYS.1.3.A13/result", value:res);
set_kb_item(name:"GSHB/SYS.1.3.A13/desc", value:desc);


# SYS.1.3.A14 Verhinderung des Ausspaehens von System- und Benutzerinformationen (C)
SYS_1_3_A14 = 'SYS.1.3.A14 Verhinderung des Ausspaehens von System- und Benutzerinformationen (C):\n';
res = 'Diese Vorgabe muss manuell überprüft werden.';
desc = '';
filenames = ["/etc/issue",
          "/proc/version",
          "/etc/debian_version",
          "/proc/sys/kernel/ostype",
          "/proc/sys/kernel/hostname",
          "/proc/sys/kernel/osrelease",
          "/proc/sys/kernel/version",
          "/proc/sys/kernel/domainname",
          "/var/log/auth.log",
          "/var/log/daemon.log",
          "/var/log/dmesg",
          "/var/log/kern.log",
          "/var/log/messages",
          "/var/log/syslog",
          "/var/log/user.log"];

foreach file (filenames) {
  cmd = "ls -lah " + file + " | cut -d' ' -f 1,3,4";
  AccessRights = ssh_cmd(socket:sock, cmd:cmd);
  if( "no such file" >< AccessRights ){
    desc += 'Die Datei "' + file + '" konnte nicht gefunden werden.\n';
  }else if( "permission denied" >< AccessRights ){
    desc += 'Keine Berechtigung für die Datei "' + file + '.\n';
  }else{
    AccessRights = split(AccessRights, sep:' ', keep:FALSE);
    desc += 'Die Datei "' + file + '" hat folgende Rechte: ' + AccessRights[0] + ', Besitzer: ' + AccessRights[1] + ', Gruppe: ' + AccessRights[2] + '.\n';
  }
}
desc += 'Es sollte manuell überprüft werden, ob der Zugriff auf die Dateien auf
das notwendige Maß beschränkt ist.\n';
SYS_1_3_A14 += desc + '\n';
set_kb_item(name:"GSHB/SYS.1.3.A14/result", value:res);
set_kb_item(name:"GSHB/SYS.1.3.A14/desc", value:desc);

# SYS.1.3.A15 Zusaetzliche Absicherung des Bootvorgangs (CIA)
SYS_1_3_A15 = 'SYS.1.3.A15 Zusätzliche Absicherung des Bootvorgangs (CIA):\n';
SYS_1_3_A15 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.1.3.A16 Zusaetzliche Verhinderung der Ausbreitung bei der Ausnutzung von Schachstellen (CI)
SYS_1_3_A16 = 'SYS.1.3.A16 Zusätzliche Verhinderung der Ausbreitung bei der Ausnutzung von Schwachstellen (CI):\n';
SYS_1_3_A16 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.1.3.A17 Zusaetzlicher Schutz des Kernels (CI)
SYS_1_3_A17 = 'SYS.1.3.A17 Zusätzlicher Schutz des Kernels (CI):\n';
SYS_1_3_A16 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

message += 'Basis-Absicherung:\n\n' + SYS_1_3_A1 + SYS_1_3_A2 + SYS_1_3_A3 + SYS_1_3_A4 + SYS_1_3_A5;
LEVEL = get_kb_item("GSHB/level");
if( LEVEL == 'Standard' || LEVEL == 'Kern'){
  message += '\n\nStandard-Absicherung:\n\n' + SYS_1_3_A6 + SYS_1_3_A7 + SYS_1_3_A8 + SYS_1_3_A9 + SYS_1_3_A10 + SYS_1_3_A11 + SYS_1_3_A12;
}
if( LEVEL == 'Kern' ){
  message += '\n\nKern-Absicherung:\n\n' + SYS_1_3_A13 + SYS_1_3_A14 + SYS_1_3_A15 + SYS_1_3_A16 + SYS_1_3_A17;
}

silence = get_kb_item("GSHB/silence");
if (!silence) log_message(port:0, data: message);


exit(0);
