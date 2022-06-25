###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_003.nasl 10396 2018-07-04 09:13:46Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 4.003
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
  script_oid("1.3.6.1.4.1.25623.1.0.94174");
  script_version("$Revision: 10396 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-04 11:13:46 +0200 (Wed, 04 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.003: Einsatz von Viren-Schutzprogrammen");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_dependencies("GSHB/GSHB_WMI_Antivir.nasl", "gather-package-list.nasl", "smb_nativelanman.nasl", "netbios_name_get.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB-15");

  script_tag(name:"summary", value:"IT-Grundschutz M4.003: Einsatz von Viren-Schutzprogrammen.

  Stand: 14. Erg‰nzungslieferung (14. EL).");

  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04003.html");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("itg.inc");
include("smb_nt.inc");

name = 'IT-Grundschutz M4.003: Einsatz von Viren-Schutzprogrammen\n';

gshbm =  "IT-Grundschutz M4.003: ";

SAMBA = kb_smb_is_samba();
SSHUNAME = get_kb_item("ssh/login/uname");

if (SAMBA || (SSHUNAME && ("command not found" >!< SSHUNAME && "CYGWIN" >!< SSHUNAME))){
  rpms = get_kb_item("ssh/login/packages");
  if (rpms){
    pkg1 = "clamav";
    pkg2 = "clamav-freshclam";

    pat1 = string("ii  (", pkg1, ") +([0-9]:)?([^ ]+)");
    pat2 = string("ii  (", pkg2, ") +([0-9]:)?([^ ]+)");
    desc1 = eregmatch(pattern:pat1, string:rpms);
    desc2 = eregmatch(pattern:pat2, string:rpms);

    name1 = desc1[1];
    version1 = desc1[3];
    name2 = desc2[1];
    version2 = desc2[3];

  }else if(rpms = get_kb_item("ssh/login/rpms")){
    tmp = split(rpms, keep:0);
    if (max_index(tmp) <= 1){
      tmp = split(rpms,sep:";", keep:0);
      rpms = "";
      for (i=0; i<max_index(tmp); i++){
      rpms += tmp[i] + '\n';
      }
    }
    pkg1 = "clamav";
    pkg2 = "clamav-freshclam";
    pkg3 = "clamav-update";

    pat1 = string("(", pkg1, ")~([0-9/.]+)~([0-9a-zA-Z/.-_]+)");
    pat2 = string("(", pkg2, ")~([0-9/.]+)~([0-9a-zA-Z/.-_]+)");
    pat3 = string("(", pkg3, ")~([0-9/.]+)~([0-9a-zA-Z/.-_]+)");
    desc1 = eregmatch(pattern:pat1, string:rpms);
    desc2 = eregmatch(pattern:pat2, string:rpms);
    desc3 = eregmatch(pattern:pat3, string:rpms);
    if (desc1){
      name1 = desc1[1];
      version1 = desc1[2];
    }
    if (desc2){
      name2 = desc2[1];
      version2 = desc2[2];
    }else if (desc3){
      name2 = desc3[1];
      version2 = desc3[2];
    }
  }else{
     rpms = get_kb_item("ssh/login/solpackages");
     pkg1 = "clamav";
     pat1 = string("([a-zA-Z0-9]+)[ ]{1,}(.*", pkg1, ".*)[ ]{1,}([a-zA-Z0-9/\._ \(\),-:\+\{\}\&]+)");

    desc1 = eregmatch(pattern:pat1, string:rpms);
    if (desc1){
      name1 = desc1[3];
    }

  }
  if(!SSHUNAME){
    result = string("Fehler");
    desc = string("Ein Login ¸ber SSH war nicht erfolgreich.");
  }else if(!rpms){
    result = string("Fehler");
    desc = string("Vom System konnte keine Paketliste mit installierter\nSoftware geladen werden.");
  }else if(SSHUNAME =~ "SunOS.*"){
    if(!desc1){
      result = string("nicht erf¸llt");
      desc = string("Die Antivirensoftware ClamAV konnte nicht auf dem\nSystem gefunden werden.");
    }else if(desc1){
      result = string("erf¸llt");
      desc = string('Die Antivirensoftware ClamAV konnte auf dem System\ngefunden werden. Folgende Version ist installiert:\n' + name1);
    }
  }else if(!desc1 && (!desc2 || !desc3)){
    result = string("nicht erf¸llt");
    desc = string("Die Antivirensoftware ClamAV konnte nicht auf dem\nSystem gefunden werden.");
  }else if(desc1 && (!desc2 && !desc3)){
    result = string("nicht erf¸llt");
    desc = string("Die Antivirensoftware ClamAV konnte auf dem System\ngefunden werden, allerdings wurde Freshclam/ClamAV-\nupdate nicht installiert.");
  }else if(desc1 && (desc2 || desc3)){
    result = string("erf¸llt");
    desc = string('Die Antivirensoftware ClamAV konnte auf dem System\ngefunden werden. Folgende Version ist installiert:\n' + name1 + "  " + version1 + '\n' + name2 + "  " + version2);
  }else{
      result = string("Fehler");
      desc = string("Beim Testen des Systems trat ein unbekannter Fehler auf.");
  }
}

else if (!SAMBA && (!SSHUNAME || "command not found" >< SSHUNAME || "CYGWIN" >< SSHUNAME)){
  log = get_kb_item("WMI/Antivir/log");
  Antivir = get_kb_item("WMI/Antivir");
  if(!Antivir) Antivir = "None";
  AntivirName = get_kb_item("WMI/Antivir/Name");
  AntivirUptoDate = get_kb_item("WMI/Antivir/UptoDate");
  if (AntivirUptoDate >!< "None") AntivirUptoDate = split(AntivirUptoDate, sep:"|", keep:0);
  AntivirEnable = get_kb_item("WMI/Antivir/Enable");
  if (AntivirEnable >!< "None") AntivirEnable = split(AntivirEnable, sep:"|", keep:0);
  AntivirState = get_kb_item("WMI/Antivir/State");
  if (AntivirState >!< "None") AntivirState = split(AntivirState, sep:"|", keep:0);

  if(Antivir >< "error"){
    result = string("Fehler");
    if(!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if(log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
  }else if(Antivir >< "Server"){
    result = string("nicht zutreffend");
    desc = string("Das System ist ein Windows Server. Solche Systeme \nkˆnnen leider nicht getestet werden");
  }else if(Antivir >< "None"){
    result = string("nicht erf¸llt");
    desc = string("Auf dem System wurde kein Antivierenprogramm gefunden");
  }else if(Antivir >< "Windows XP <= SP1"){
    result = string("nicht zutreffend");
    desc = string("Das System ist ein Windows XP System kleiner oder\ngleich Service Pack 1 und kann nicht getestet werden");
  }else if(AntivirName >!< "None" && AntivirState >< "None"){
      if ("True" >< AntivirEnable[2] && "True" >< AntivirUptoDate[2]){
        result = string("erf¸llt");
        desc = string("Das System hat einen Virenscanner installiert,\nwelcher l‰uft und aktuell ist.");
      }else if ("True" >< AntivirEnable[2] && "False" >< AntivirUptoDate[2]){
        result = string("nicht erf¸llt");
        desc = string("Das System hat einen Virenscanner istalliert,\nwelcher l‰uft aber veraltet ist.");
      }else if ("False" >< AntivirEnable[2] && "True" >< AntivirUptoDate[2]){
        result = string("nicht erf¸llt");
        desc = string("Das System hat einen Virenscanner installiert,\nwelcher aus aber aktuell ist.");
      }else if ("False" >< AntivirEnable[2] && "False" >< AntivirUptoDate[2]){
        result = string("nicht erf¸llt");
        desc = string("Das System hat einen Virenscanner installiert,\nwelcher aus und veraltet ist.");
      }
  }else if(AntivirName >!< "None" && AntivirState >!< "None"){
      if ("266240" >< AntivirState[2]){
        result = string("erf¸llt");
        desc = string("Das System hat einen Virenscanner installiert,\nwelcher l‰uft und aktuell ist.");
      }else if ("266256" >< AntivirState[2]){
        result = string("nicht erf¸llt");
        desc = string("Das System hat einen Virenscanner installiert,\nwelcher l‰uft aber veraltet ist.");
      }else if ("262144"  >< AntivirState[2] || "270336" >< AntivirState[2]){
        result = string("nicht erf¸llt");
        desc = string("Das System hat einen Virenscanner installiert,\nwelcher aus aber aktuell ist.");
      }else if ("262160"  >< AntivirState[2] || "270352" >< AntivirState[2]){
        result = string("nicht erf¸llt");
        desc = string("Das System hat einen Virenscanner installiert,\nwelcher aus und veraltet ist.");
      }
  }else{
      result = string("Fehler");
      desc = string("Beim Testen des Systems trat ein unbekannter\nFehler auf.");
  }
}

else{
      result = string("Fehler");
      desc = string("Beim Testen des Systems trat ein unbekannter\nFehler auf.");
}

set_kb_item(name:"GSHB/M4_003/result", value:result);
set_kb_item(name:"GSHB/M4_003/desc", value:desc);
set_kb_item(name:"GSHB/M4_003/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_003');

exit(0);
