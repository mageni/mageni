##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SYS.2.3.nasl 12387 2018-11-16 14:06:23Z cfischer $
#
# IT-Grundschutz Baustein: SYS.2.3 Clients unter Unix
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
  script_oid("1.3.6.1.4.1.25623.1.0.109038");
  script_version("$Revision: 12387 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 15:06:23 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-12-19 15:30:28 +0100 (Tue, 19 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('SYS.2.3 Clients unter Unix');
  script_xref(name:"URL", value:"https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_2_3_Clients_unter_Unix.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_dependencies("GSHB/GSHB_SSH_AppArmor_SeLinux.nasl", "GSHB/GSHB_SSH_quota.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB-ITG");

  script_tag(name:"summary", value:"Zielsetzung dieses Bausteins ist der Schutz von Informationen,
  die auf Unix-Clients erstellt, bearbeitet, gespeichert oder versendet werden");

  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");

Distribution = get_kb_item("ssh/login/release");
if( ! Distribution ){
  log_message(data:'Es konnte keine Linux-Distribution erkannt werden.\n', port:0);
  req = make_list("A1","A2","A3","A4","A5","A6","A7","A8","A9","A10","A11",
      "A12","A13","A14","A15","A16","A17","A18","A19","A20");
  foreach r (req){
    set_kb_item(name:"GSHB/SYS.2.3." + r + "/result", value:"nicht zutreffend");
    set_kb_item(name:"GSHB/SYS.2.3." + r + "/desc", value:"Auf dem Host ist kein Linux installiert.");
  }
  exit(0);
}

port = kb_ssh_transport();
host_ip = get_host_ip();

sock = ssh_login_or_reuse_connection();
if( !sock ) {
  error = get_ssh_error();
  if( !error ){
    error = "No SSH Port or Connection!";
    log_message(port:port, data:error);
    exit(0);
  }
}


# SYS.2.3.A1 Authentisierung von Administratoren und Benutzer [Benutzer]
SYS_2_3_A1 = 'SYS.2.3.A1 Authentisierung von Administratoren und Benutzer:\n';
res = 'erfüllt';
desc = 'Benutzer sollten sich nicht gleichzeitig auf einem Gerät einloggen können:\n';
max_auth = ssh_cmd( socket:sock, cmd:'cat /etc/security/limits.conf | grep -v "^#" | grep maxlogins');
if( max_auth ){
max_auth = split(max_auth, keep:FALSE);
  foreach line (max_auth){
    line = ereg_replace( pattern:'\\s', string:line, replace:'|', icase:TRUE );
    line = split(line, sep:'|', keep:FALSE);
    if( line[max_index(line) -1] != "1" ){
      group += line[0] + ', ' + line[max_index(line)-1 ] + '.\n';
    }
  }
  if( group ){
    desc += 'Benutzer folgender Gruppen können sich gleichzeitig einloggen (User, max. Anzahl):\n' + group;
  }else{
    desc += 'Es konnten keine Benutzergruppen gefunden werden, die sich gleichzeitig einloggen können.\n';
  }

}else{
  desc += 'In der Datei "/etc/security/limits.conf" konnte kein Eintrag zur Verhinderung
von gleichzeitigem Login gefunden werden.\n';
  res = 'nicht erfüllt';
}

sudo = ssh_cmd( socket:sock, cmd:"dpkg -s sudo");
desc += 'Für Systemadministrationsaufgaben sollte "sudo" oder eine geeignete Alternative
verwendet werden:\n';
if( "status: install ok installed" >< tolower(sudo) ){
  desc += 'Das Paket sudo ist installiert.\n';
}else{
  desc += 'Das Paket sudo ist nicht installiert. Dies oder eine geeignete Alternative
sollte installiert sein.\n';
}

desc += 'Bitte stellen Sie sicher, dass Administratoren sich nicht im Normalbetrieb
als root anmelden.\n';

SYS_2_3_A1 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.3.A1/result", value:res);
set_kb_item(name:"GSHB/SYS.2.3.A1/desc", value:desc);

# SYS.2.3.A2 Auswahl einer geeigneten Distribution
SYS_2_3_A2 += 'SYS.2.3.A2 Auswahl einer geeigneten Distribution:\n';
res = 'erfüllt';
if( get_kb_item("ssh/login/gentoo") ){
  desc = 'Die erkannte Distribution "Gentoo" ist ein Rolling-Release-Modell.
Solche Distributionen sollten nicht verwendet werden.\n';
  res = 'nicht erfüllt';
}else{
  desc = 'Es konnte keine Distribution mit einem Rolling-Release-Modell
    erkannt werden. Erkanntes OS: ' + Distribution + '\n';
}

SYS_2_3_A2 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.3.A2/result", value:res);
set_kb_item(name:"GSHB/SYS.2.3.A2/desc", value:desc);

# SYS.2.3.A3 Cloud- und Online-Inhalte
SYS_2_3_A3 += 'SYS.2.3.A3 Cloud- und Online-Inhalte:\n';
SYS_2_3_A3 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.2.3.A4 Einspielen von Updates und Patches
SYS_2_3_A4 = 'SYS.2.3.A4 Einspielen von Updates und Patches:\n';
res = 'erfüllt';
desc = 'Bitte führen Sie einen Schwachstellen-Scan gegen den Client aus,
um evtl Schwachstellen zu detektieren.\n';
LivepatchEnabled = ssh_cmd(socket:sock, cmd:"ls -l /sys/kernel/ | grep livepatch");
if( ! LivepatchEnabled ){
  desc += 'Live-Patching des Kernels ist nicht aktiviert.
Der Client sollte nach Updates zeitnah rebootet werden.\n';
}else if( "no such file or directory" >< LivepatchEnabled ){
  desc += 'Auf dem Host existiert "/sys/kernel" nicht.
Der Status des Live-Patching kann nicht ermittelt werden.\n';
}else if( "permission denied" >< LivepatchEnabled ){
  desc += 'Der Zugriff auf "/sys/kernel" wurde verweigert.
Der Status des Live-Patching kann nicht ermittelt werden.\n';
}else{
  desc += 'Live-Patching des Kernels ist aktiviert.\n';
  InstalledPatches = ssh_cmd(socket:sock, cmd:"ls -l /sys/kernel/livepatch/");
  if( InstalledPatches ){
    desc += 'Folgende Patches sind installiert:\n' + InstalledPatches + '\n';
  }else{
    desc += 'Es konnten keine installierten Patches gefunden werden.\n';
  }
}

SYS_2_3_A4 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.3.A4/result", value:res);
set_kb_item(name:"GSHB/SYS.2.3.A4/desc", value:desc);


# SYS.2.3.A5 Sichere Installation von Software-Paketen
SYS_2_3_A5 += 'SYS.2.3.A5 Sichere Installation von Software-Paketen:\n';
SYS_2_3_A5 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.2.3.A6 Automatisches Einbinden von Wechsellaufwerken [Benutzer]
SYS_2_3_A6 = 'SYS.2.3.A6 Automatisches Einbinden von Wechsellaufwerken:\n';
res = 'erfüllt';
cmd = 'dpkg -s autofs';
Autofs = ssh_cmd(socket:sock, cmd:cmd);
if( "install ok installed" >< tolower(Autofs) ){
  desc = 'Das Paket "autofs" scheint auf dem Host installiert zu sein.
Dies kann automatisches Einbinden von Wechsellaufwerken zur Folge haben und sollte
daher entfernt werden.\n';
  res = 'nicht erfüllt';
}else if( ! Autofs ){
  desc = 'Es konnte nicht ermittelt werden, ob das Paket "autofs" auf dem Host installiert ist.\n';
  res = 'error';
}else{
  desc = 'Das Paket "autofs", welches Laufwerke automatisch einbindet, ist nicht auf dem Host installiert.\n';
}

cmd = 'dpkg -s usbmount';
USBmount = ssh_cmd(socket:sock, cmd:cmd);
if( "install ok installed" >< tolower(USBmount) ){
  desc += 'Das Paket "usbmount" scheint auf dem Host installiert zu sein.
Dies kann automatisches Einbinden von USB-Laufwerken zur Folge haben und sollte
daher entfernt werden.\n';
  res = 'nicht erfüllt';
}else if( ! USBmount ){
  desc += 'Es konnte nicht ermittelt werden, ob das Paket "usbmount" auf dem Host installiert ist.\n';
  res = 'error';
}else{
  desc += 'Das Paket "usbmount", welches USB-Laufwerke automatisch einbindet, ist nicht auf dem Host installiert.\n';
}

Missing_Noexec = ssh_cmd(socket:sock, cmd:"grep -vE '^#|noexec' /etc/fstab | grep '/media/'");
desc += 'Wechsellaufwerke sollten die Mountoption "noexec" besitzen:\n';
if( "command not found" >< Missing_Noexec ){
  desc += 'Fehler: Die Datei "/etc/fstab" konnte nicht gelesen werden.\n';
  res = 'error';
}else if( "permission denied" >< Missing_Noexec ){
  desc += 'Fehler: Die Datei "/etc/fstab" konnte nicht gelesen werden.\n';
  res = 'error';
}else if( "no such file or directory" >< Missing_Noexec ){
  desc += 'Fehler: Die Datei "/etc/fstab" konnte nicht gefunden werden.\n';
  res = 'error';
}else if( ! Missing_Noexec ){
  desc += 'Es wurden keine Partitionen im Einhängepunkt "/media/"  ohne die Option "noexec" gefunden.\n';
}else{
  desc += 'Folgende Partitionen im Einhängepunkt "/media/" haben die "noexec" Option nicht gesetzt:\n'
    + Missing_Noexec + '\n';
  res = 'nicht erfüllt';
}

SYS_2_3_A6 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.3.A6/result", value:res);
set_kb_item(name:"GSHB/SYS.2.3.A6/desc", value:desc);


# SYS.2.3.A7 Restriktive Rechtevergabe auf Dateien und Verzeichnisse
SYS_2_3_A7 += 'SYS.2.3.A7 Restriktive Rechtevergabe auf Dateien und Verzeichnisse:\n';
res = 'erfüllt';
GlobalDirectories = ssh_cmd(socket:sock, cmd:"find / -maxdepth 3 -type d -perm -777");
if( GlobalDirectories ){
  GlobalDirectories = split(GlobalDirectories, keep:FALSE);
  foreach Dir (GlobalDirectories){
    if( "permission denied" >< tolower(Dir) ){
      continue;
    }else{
      cmd = "ls -ld " + Dir;
      Perm = ssh_cmd(socket:sock, cmd:cmd);
      StickyBit=ereg(string:Perm, pattern:"d[r,w,x,-]{8}t", icase:TRUE);
      if( ! StickyBit == '1' ){
        NoStickyBit += Dir + '\n';
      }
    }
  }
  if( NoStickyBit ){
    desc = 'Folgende global les- und schreibbare Verzeichnisse haben das StickyBit
nicht gesetzt:\n ' + NoStickyBit;
    res = 'nicht erfüllt';
  }else{
    desc = 'Es wurden keine global les- und schreibbare Verzeichnisse ohne das
StickyBit gefunden.\n';
  }
}else{
  desc = 'Es wurden keine global les- und schreibbaren Verzeichnisse gefunden.';
}

SYS_2_3_A7 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.3.A7/result", value:res);
set_kb_item(name:"GSHB/SYS.2.3.A7/desc", value:desc);

# SYS.2.3.A8 Einsatz von Techniken zur Rechtebeschränkung von Anwendungen
SYS_2_3_A8 = 'SYS.2.3.A8 Einsatz von Techniken zur Rechtebeschränkung von Anwendungen:\n';
res = 'nicht erfüllt';
desc = '';
AppArmor_Basic = get_kb_item("GSHB/AppArmor_Basic");
if( AppArmor_Basic == '1' ) {
  desc += 'App-Armor ist auf dem Host installiert. Anwendungen sollten durch
Whitelisting reglementiert und Profile sollten im Enforced Mode oder mit
geeigneten Alternativen verwendet werden.\n';
  res = 'erfüllt';
}

SELinux_Basics = get_kb_item("GSHB/SeLinux_Basics");
if( SELinux_Basics == '1' ){
  desc += 'SeLinux ist auf dem Host installiert. Anwendungen sollten durch
Whitelisting reglementiert und Profile sollten im Enforced Mode oder mit
geeigneten Alternativen verwendet werden.\n';
  res = 'erfüllt';
}

if( res == 'nicht erfüllt' ){
  desc += 'Weder AppArmor noch SeLinux konnten auf dem Client identifiziert werden.
Auf dem Client sollte AppArmor oder SeLinux installiert werden, sodass Anwendungen
mittels Whitelisting reglementiert und Profile im Enforced Mode oder
mit geeigneten Alternativen verwendet werden.\n';
}

SYS_2_3_A8 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.3.A8/result", value:res);
set_kb_item(name:"GSHB/SYS.2.3.A8/desc", value:desc);

# SYS.2.3.A9 Passwörter auf der Kommandozeile [Benutzer]
SYS_2_3_A9 = 'SYS.2.3.A9 Passwörter auf der Kommandozeile:\n';
SYS_2_3_A9 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.2.3.A10 Absicherung des Bootvorgangs
SYS_2_3_A10 = 'SYS.2.3.A10 Absicherung des Bootvorgangs:\n';
res = 'nicht erfüllt';
GrubConf = ["/boot/grub/menu.lst",
  "/etc/grub.conf",
  "/boot/grub/grub.conf",
  "/etc/grub.cfg",
  "/boot/grub/grub.cfg"];

foreach file (GrubConf) {
  cmd = "cat " + file + ' | grep "password"';
  GrubConfFile = ssh_cmd(socket:sock, cmd:cmd);
  if( "no such file or directory" >< GrubConfFile ){
    continue;
  }else if( ! GrubConfFile ){
    GrubPasswd = "nicht aktiviert. Dies sollte aktiviert werden.";
  }else{
    GrubPasswd = "aktiviert.";
    res = 'erfüllt';
  }
}

desc = 'Absicherung des Bootloaders:\n';
if( GrubPasswd ){
  desc += 'Der Bootloader "Grub" wird verwendet und ein Passwortschutz ist ' + GrubPasswd + '\n';
}else{
  desc += 'Der Bootloader "Grub" wird nicht verwendet oder es konnte keine
Grub-Konfigurationsdatei gefunden werden. Ein Bootloader sollte mit einem Passwort
abgesichert werden.\n';
}

UEFI = ssh_cmd(socket:sock, cmd:'ls -l /sys/firmware/ | grep "efi"');
desc += 'Prüfung der Integrität vom Bootloader bis zum Kernel:\n';
if( ! UEFI ){
  desc += 'UEFI wird nicht genutzt. Secure Boot oder äquivalente Lösungen
sollten genutzt werden.\n';
}else{
  SecureBoot = ssh_cmd(socket:sock, cmd:"mokutil --sb-state");
  if( "command not found" >< SecureBoot ){
    desc += 'UEFI wird verwendet, der Status von Secure Boot konnte jedoch
nicht ermittelt werden. Secure Boot oder äquivalente Lösungen sollte genutzt werden.\n';
  }else if( "enabled" >< SecureBoot ){
    desc += 'UEFI und Secure Boot wird genutzt.\n';
  }else{
    desc += 'UEFI wird verwendet, Secure Boot wird jedoch nicht genutzt.
Secure Boot oder äquivalente Lösungen sollten genutzt werden.\n';
    res = 'nicht erfüllt';
  }
}

SYS_2_3_A10 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.3.A10/result", value:res);
set_kb_item(name:"GSHB/SYS.2.3.A10/desc", value:desc);

# SYS.2.3.A11 Verhinderung der Überlastung der Festplatte
SYS_2_3_A11 = 'SYS.2.3.A11 Verhinderung der Überlastung der Festplatte:\n';
fstabQuota = get_kb_item("GSHB/quota/fstab");
aquotauser = get_kb_item("GSHB/quota/user");
aquotagroup = get_kb_item("GSHB/quota/group");
res = 'erfüllt';

if( ! fstabQuota || fstabQuota == "none" ){
  desc = 'Es werden keine Patitionen mit Quotas beschränkt. Quotas sollte eingerichtet
werden, um eine Überlastung der Festplatten zu verhindern.\n';
  res = 'nicht erfüllt';
}else if( fstabQuota == "nogrep" ){
  desc = 'Fehler: Die Datei "/etc/fstab" konnte nicht gelesen werden.\n';
  res = 'error';
}else{
  desc = 'Folgende Geräte und Partitionen werden mit Quota eingeschränkt:\n' +
    fstabQuota + '\n';
}

if( ! aquotauser || aquotauser == "none" || aquotauser == "nols" ){
  desc += 'Die Datei "aquota.user" konnte nicht gefunden oder gelesen werden.
Quotas ist nicht korrekt konfiguriert.\n';
  res = 'nicht erfüllt';
}
if( ! aquotagroup || aquotagroup == "none" || aquotagroup == "nols" ){
  desc += 'Die Datei "aquota.group" konnte nicht gefunden oder gelesen werden.
Quotas ist nicht korrekt konfiguriert.\n';
  res = 'nicht erfüllt';
}
SYS_2_3_A11 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.3.A11/result", value:res);
set_kb_item(name:"GSHB/SYS.2.3.A11/desc", value:desc);


# SYS.2.3.A12 Einsatz von Appliances als Clients
SYS_2_3_A12 = 'SYS.2.3.A12 Einsatz von Appliances als Clients:\n';
SYS_2_3_A12 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.2.3.A13 Schutz vor unbefugten Anmeldungen (CIA)
SYS_2_3_A13 = 'SYS.2.3.A13 Schutz vor unbefugten Anmeldungen (CIA):\n';
res = 'Diese Vorgabe muss manuell überprüft werden.';
PAM_PKCS11 = ssh_cmd( socket:sock, cmd:'cat /etc/pam.d/login | grep "required" | grep -v "^#" | grep "pam_pkcs11.so"');
PAM_POLDI = ssh_cmd( socket:sock, cmd:'cat /etc/pam.d/login | grep "required" | grep -v "^#" | grep "pam_poldi.so"');

if( PAM_PKCS11 ){
  desc = 'Das Modul "pam_pkcs11" zur Authentifizierung mittels einer SmartCard
ist auf dem Client vorhanden. Die korrekte Konfiguration für eine Zwei-Faktor-
Authentisierung sollte manuell geprüft werden.\n';
}else if( PAM_POLDI ){
  desc = 'Das Modul "pam_poldi" zur Authentifizierung mittels einer SmartCard
ist auf dem Client vorhanden. Die korrekte Konfiguration für eine Zwei-Faktor-
Authentisierung sollte manuell geprüft werden.\n';
}else{
  desc = 'Weder das Modul "pam_poldi" noch "pam_pkcs11", welche die Authentifizierung
mittels SmartCard unterstützen, sind auf dem Client vorhanden. Bitte stellen Sie
sicher, dass eine geeignete Alternative für eine Zwei-Faktor-Authentisierung
verwendet wird.\n';
}

SYS_2_3_A13 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.3.A13/result", value:res);
set_kb_item(name:"GSHB/SYS.2.3.A13/desc", value:desc);

# SYS.2.3.A14 Absicherung gegen Nutzung unbefugter Peripheriegeräte (CIA)
SYS_2_3_A14 = 'SYS.2.3.A14 Absicherung gegen Nutzung unbefugter Peripheriegeräte (CIA):\n';
res = 'nicht erfüllt';
cmd = 'cat /etc/sysctl.conf | grep -v "^#" | grep "kernel.modules_disabled=1"';
AutoloadKernelModules = ssh_cmd(socket:sock, cmd:cmd);

if( "permission denied" >< tolower(AutoloadKernelModules) ||
    "no such file" >< tolower(AutoloadKernelModules) ){
  desc = 'Fehler: Die Systemeinstellungen konnten nicht gelesen werden.\n';
  res = 'error';
}else if( AutoloadKernelModules ){
  desc = 'Neue Kernelmodule können nicht automatisch geladen und aktiviert werden.\n';
  res = 'erfüllt';
}else{
  desc = 'Neue Kernelmodule können automatisch geladen und aktiviert werden.
Dies sollte verhindert werden.\n';
}

SYS_2_3_A14 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.3.A14/result", value:res);
set_kb_item(name:"GSHB/SYS.2.3.A14/desc", value:desc);


# SYS.2.3.A15 Zusätzlicher Schutz vor der Ausführung unerwünschter Dateien (CI)
SYS_2_3_A15 = 'SYS.2.3.A15 Zusätzlicher Schutz vor der Ausführung unerwünschter Dateien (CI):\n';
MntWithoutNoexec = ssh_cmd(socket:sock, cmd:'findmnt -l | grep rw | grep -v "noexec"');
res = 'nicht erfüllt';
if( "command not found" >< tolower(MntWithoutNoexec) ||
    "permission denied" >< tolower(MntWithoutNoexec) ){
  desc = 'Fehler: Die gemounteten Partitionen und Verzeichnisse konnten
    nicht gelesen werden.\n';
    res = 'error';
}else if( MntWithoutNoexec ){
  desc = 'Bei folgenden schreibbaren Partitionen und Verzeichnissen
fehlt die "noexec"-Option:\n' + MntWithoutNoexec + '\n';
}else{
    desc = 'Es konnten keine beschreibbaren Partitionen ohne die "noexec"
    Option gefunden werden.\n';
    res = 'erfüllt';
}

SYS_2_3_A15 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.3.A15/result", value:res);
set_kb_item(name:"GSHB/SYS.2.3.A15/desc", value:desc);

# SYS.2.3.A16 Zusätzliche Absicherung des Bootvorgangs (CIA)
SYS_2_3_A16 = 'SYS.2.3.A16 Zusätzliche Absicherung des Bootvorgangs (CIA):\n';
SYS_2_3_A16 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.2.3.A17 Zusätzliche Verhinderung der Ausbreitung bei der Ausnutzung von Schwachstellen (CI)
SYS_2_3_A17 = 'SYS.2.3.A17 Zusätzliche Verhinderung der Ausbreitung bei der Ausnutzung von Schwachstellen (CI):\n';
res = 'erfüllt';
Seccomp = ssh_cmd(socket:sock, cmd:"dpkg -s seccomp");
if( "install ok installed" >< Seccomp ){
  desc = 'Das Paket "seccomp" ist installiert. Die korrekte Konfiguration
sollte manuell überprüft werden.\n';
}else{
  desc = 'Das Paket "seccomp" ist nicht installiert. Dies sollte installiert
und konfiguriert werden.\n';
}
desc += 'Zusätzlich sollten die aktiven Profile von "SeLinux" oder "AppArmor"
manuell überprüft werden.\n';

SYS_2_3_A17 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.3.A17/result", value:res);
set_kb_item(name:"GSHB/SYS.2.3.A17/desc", value:desc);


# SYS.2.3.A18 Zusätzlicher Schutz des Kernels (CI)
SYS_2_3_A18 = 'SYS.2.3.A18 Zusätzlicher Schutz des Kernels (CI):\n';
SYS_2_3_A18 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.2.3.A19 Festplatten- oder Dateiverschlüsselung (CI)
SYS_2_3_A19 = 'SYS.2.3.A19 Festplatten- oder Dateiverschlüsselung (CI):\n';
SYS_2_3_A19 += 'Diese Vorgabe muss manuell überprüft werden.\n\n';

# SYS.2.3.A20 Abschaltung kritischer SysRq-Funktionen (CIA)
SYS_2_3_A20 = 'SYS.2.3.A20 Abschaltung kritischer SysRq-Funktionen (CIA):\n';
res = "Diese Vorgabe muss manuell überprüft werden.";
SysRq = ssh_cmd(socket:sock, cmd:"cat /proc/sys/kernel/sysrq");
if( "permission denied" >< tolower(SysRq) ||
    "no such file" >< tolower(SysRq) ){
  desc = 'Fehler: Die Datei "/proc/sys/kernel/sysrq" konnte nicht gelesen
    werden.\n';
    res = 'error';
}else if( "no such file or directory" >< tolower(SysRq) ||
    SysRq == "0" ){
  desc = 'Die SysRq-Funktionen sind deaktiviert.\n';
  res = "erfüllt";
}else if( SysRq == "1" ){
  desc = 'Es sind sämtliche SysRq-Funktionen aktiviert. Diese sollten deaktiviert werden.\n';
  res = "nicht erfüllt";
}else if( SysRq > "1" ){
  desc = 'SysRq-Funktionen sind aktiviert. Bitte prüfen Sie manuell,
ob diese notwendig oder kritisch sind.\n';
  res = 'nicht erüllt';
}else{
  desc = 'Fehler: Ein unbekannter Fehler ist aufgetreten. Bitte prüfen Sie manuell,
ob kritische SysRq-Funktionen abgeschaltet sind.\n';
  res = "error";
}

SYS_2_3_A20 += desc + '\n';
set_kb_item(name:"GSHB/SYS.2.3.A20/result", value:res);
set_kb_item(name:"GSHB/SYS.2.3.A20/desc", value:desc);

message += 'Basis-Absicherung:\n\n' + SYS_2_3_A1 + SYS_2_3_A2 + SYS_2_3_A3;
message += SYS_2_3_A4 + SYS_2_3_A5;
LEVEL = get_kb_item("GSHB/level");
if( LEVEL == 'Standard' || LEVEL == 'Kern'){
  message += '\n\nStandard-Absicherung:\n\n' + SYS_2_3_A6 + SYS_2_3_A7 + SYS_2_3_A8;
  message += SYS_2_3_A9 + SYS_2_3_A10 + SYS_2_3_A11 + SYS_2_3_A12;
}
if( LEVEL == 'Kern' ){
  message += '\n\nKern-Absicherung:\n\n' + SYS_2_3_A13 + SYS_2_3_A14 + SYS_2_3_A15;
  message += SYS_2_3_A16 + SYS_2_3_A17 + SYS_2_3_A18 + SYS_2_3_A19 + SYS_2_3_A20;
}

silence = get_kb_item("GSHB/silence");
if (!silence) log_message(port:0, data: message);

ssh_close_connection( sock );
exit(0);
