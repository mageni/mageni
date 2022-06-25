###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_147.nasl 10623 2018-07-25 15:14:01Z cfischer $
#
# IT-Grundschutz, 15. EL, Maßnahme 4.147
#
# Authors:
# Thomas Rotter <thomas.rotter@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.94217");
  script_version("$Revision: 10623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("IT-Grundschutz M4.147: Sichere Nutzung von EFS unter Windows");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04147.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_WMI_EFS.nasl", "GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_SMB_SDDL.nasl", "GSHB/GSHB_WMI_Hibernate.nasl");
  script_require_keys("WMI/WMI_EncrDir", "WMI/WMI_EncrFile", "WMI/WMI_EFSAlgorithmID");
  script_tag(name:"summary", value:"IT-Grundschutz M4.147: Sichere Nutzung von EFS unter Windows.

Stand: 15. Ergänzungslieferung (15. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M4.147: Sichere Nutzung von EFS unter Windows\n';

OSVER = get_kb_item("WMI/WMI_OSVER");
OSNAME = get_kb_item("WMI/WMI_OSNAME");
OSSP = get_kb_item("WMI/WMI_OSSP");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
EncrFile = get_kb_item("WMI/WMI_EncrFile");
EncrFile = ereg_replace(pattern:'Name\n', string:EncrFile, replace:'');
EncrDir = get_kb_item("WMI/WMI_EncrDir");
EncrDir = ereg_replace(pattern:'Name\n', string:EncrDir, replace:'');
EFSAlgorithmID = get_kb_item("WMI/WMI_EFSAlgorithmID");
AUTOEXECSDDL = get_kb_item("GSHB/AUTOEXECSDDL");
log = get_kb_item("WMI/WMI_EFS/log");
stat =  get_kb_item("GSHB/WINSDDL/stat");

if (OSVER == '5.0')
{
#Jeder
if(AUTOEXECSDDL =~ "\(A;.*;0x001f01ff;;;WD\)") USER += "Jeder - Vollzugriff, ";
if(AUTOEXECSDDL =~ "\(A;.*;0x001301bf;;;WD\)") USER += "Jeder - Ändern, ";
if(AUTOEXECSDDL =~ "\(A;.*;0x001201bf;;;WD\)") USER += "Jeder - Schreiben, ";
#Authentifizierte User
if(AUTOEXECSDDL =~ "\(A;.*;0x001f01ff;;;AU\)") USER += "Authentifizierte User - Vollzugriff, ";
if(AUTOEXECSDDL =~ "\(A;.*;0x001301bf;;;AU\)") USER += "Authentifizierte User - ändernden Zugriff, ";
if(AUTOEXECSDDL =~ "\(A;.*;0x001201bf;;;AU\)") USER += "Authentifizierte User - schreibenden Zugriff, ";
#Benutzer
if(AUTOEXECSDDL =~ "\(A;.*;0x001f01ff;;;S-1-5-32-545\)") USER += "Benutzer - Vollzugriff, ";
if(AUTOEXECSDDL =~ "\(A;.*;0x001301bf;;;S-1-5-32-545\)") USER += "Benutzer - ändernden Zugriff, ";
if(AUTOEXECSDDL =~ "\(A;.*;0x001201bf;;;S-1-5-32-545\)") USER += "Benutzer - schreibenden Zugriff, ";
#Hauptbenutzer
if(AUTOEXECSDDL =~ "\(A;.*;0x001f01ff;;;S-1-5-32-547\)") USER += "Hauptbenutzer - Vollzugriff, ";
if(AUTOEXECSDDL =~ "\(A;.*;0x001301bf;;;S-1-5-32-547\)") USER += "Hauptbenutzer - ändernden Zugriff, ";
if(AUTOEXECSDDL =~ "\(A;.*;0x001201bf;;;S-1-5-32-547\)") USER += "Hauptbenutzer - schreibenden Zugriff, ";
#Gäste
if(AUTOEXECSDDL =~ "\(A;.*;0x001f01ff;;;BG\)") USER += "Gäste - Vollzugriff, ";
if(AUTOEXECSDDL =~ "\(A;.*;0x001301bf;;;BG\)") USER += "Gäste - ändernden Zugriff, ";
if(AUTOEXECSDDL =~ "\(A;.*;0x001201bf;;;BG\)") USER += "Gäste - schreibenden Zugriff, ";
}

if (EFSAlgorithmID == "none")
{
    if (OSVER == '5.0'){
      EFSAlgorithmID = "DESX";
    }else if (OSVER == '5.1' &&  OSSP == "Without SP"){
      EFSAlgorithmID = "DESX";
    }else if (OSVER == '5.1' &&  OSSP >= 1){
      EFSAlgorithmID = "AES-256";
    }
}
else if (EFSAlgorithmID == "6603"){
  EFSAlgorithmID = "3DES";
}
else if (EFSAlgorithmID == "6604"){
  EFSAlgorithmID = "DESX";
}
else if (EFSAlgorithmID == "6610"){
  EFSAlgorithmID = "AES-256";
}

gshbm =  "IT-Grundschutz M4.147: ";

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System läuft Samba, es ist kein\nMicrosoft Windows System.");
  }else if(!stat){
    result = string("Fehler");
    desc = string("Beim Testen des Systems trat ein Fehler auf.\nEs konnte keine File and Folder ACL abgerufen werden.");
  }else if(EncrFile >< "error" && EncrDir >< "error" && EFSAlgorithmID >< "error"){
    result = string("Fehler");
    if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
} else if(OSVER == '5.0' || OSVER == '5.1' || OSNAME >< 'Microsoft(R) Windows(R) XP Professional x64 Edition' || (OSVER > '5.2' && OSTYPE == 1)){

    if (EncrFile  == "none" && EncrDir == "none"){
      result = string("nicht zutreffend");
      desc = string("Auf dem Systems gibt es keine EFS-verschlüsselten\nDaten.");
    }

    else{

      if (OSVER > '5.0'){
        result = string("erfüllt");
        desc = string('Auf dem Systems gibt es folgende EFS-verschlüsselten\nDaten:\n' + EncrDir +  EncrFile + '\nDabei wird folgendes Verschlüsselungsverfahren\neingesetzt: ' + EFSAlgorithmID + '\nBitte beachten Sie auch, dass Sie ein dediziertes\nKonto für den Wiederherstellungsagenten erzeugen und\ndessen privaten Schlüssel sichern und aus dem System\nentfernen sollten. Außerdem sollten Sie die syskey-\nVerschlüsselung mit Passwort verwendet, wenn EFS mit\nlokalen Konten eingesetzt wird');
      }else{

        if(USER){
          result = string("nicht erfüllt");
          desc = string('Auf dem System existieren EFS-verschlüsselte Dateien.\nDabei haben folgende Benutzer\n' + USER + '\nzugriff auf die Datei autoexec.bat.\nDie Windows Boot-Datei autoexec.bat muss vor\nVerschlüsselung geschützt werden, indem für Benutzer\nder Schreibzugriff unterbunden wird, da sonst eine\nDenial-of-Service-Attacke möglich ist.');
        }else{
        result = string("erfüllt");
        desc = string('Auf dem Systems gibt es folgende EFS-verschlüsselten\nDaten:\n' + EncrDir +  EncrFile + '\nDabei wird folgendes Verschlüsselungsverfahren\neingesetzt: ' + EFSAlgorithmID + '\nBitte beachten Sie auch, dass Sie ein dediziertes\nKonto für den Wiederherstellungsagenten erzeugen und\\ndessen privaten Schlüssel sichern und aus dem System\nentfernen sollten. Außerdem sollten Sie die syskey-\nVerschlüsselung mit Passwort verwendet, wenn EFS mit\nlokalen Konten eingesetzt wird');
        }

      }
    }

} else{
  result = string("nicht zutreffend");
  desc = string("Das System ist kein Windows Client");
}

set_kb_item(name:"GSHB/M4_147/result", value:result);
set_kb_item(name:"GSHB/M4_147/desc", value:desc);
set_kb_item(name:"GSHB/M4_147/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_147');

exit(0);
