###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_049.nasl 10623 2018-07-25 15:14:01Z cfischer $
#
# IT-Grundschutz, 15. EL, Maﬂnahme 4.049
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
  script_oid("1.3.6.1.4.1.25623.1.0.94205");
  script_version("$Revision: 10623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("IT-Grundschutz M4.049: Absicherung des Boot-Vorgangs f¸r ein Windows-System");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04049.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_WMI_BootDrive.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_keys("WMI/FS", "WMI/FDD", "WMI/CD", "WMI/USB", "WMI/BOOTINI");
  script_tag(name:"summary", value:"IT-Grundschutz M4.049: Absicherung des Boot-Vorgangs f¸r ein Windows-System.

Stand: 15. Erg‰nzungslieferung (15. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M4.049: Absicherung des Boot-Vorgangs f¸r ein Windows-System\n';

gshbm =  "IT-Grundschutz M4.049: ";

FS= get_kb_item("WMI/FS");
FDD = get_kb_item("WMI/FDD");
CD = get_kb_item("WMI/CD");
USB = get_kb_item("WMI/USB");
BOOTINI = get_kb_item("WMI/BOOTINI");
log = get_kb_item("WMI/BOOTDRIVE/log");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");


if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba, es ist kein\nMicrosoft Windows System.");
}else if("error" >< FS || "error" >< FDD || "error" >< CD || "error" >< USB || "error" >< BOOTINI){
  result = string("Fehler");
  if (!log)desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log)desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if("None" >< FS && "None" >< FDD && "None" >< CD && "None" >< USB || "none" >< BOOTINI){
  result = string("Fehler");
  desc = string("Beim Testen des Systems trat ein Fehler auf.");
}else if("True" >< BOOTINI || "None" >!< FDD || "None" >!< CD || "None" >!< USB || "FAT" >< FS){
  result = string("nicht erf¸llt");
  if("True" >< BOOTINI) desc =string("Boot.ini ist beschreibbar, bitte achten Sie darauf,\ndass die Boot.ini schreibgesch¸tzt ist und ent-\nsprechende NTFS Berechtigungen gesetzt sind." + '\n');
  if("None" >!< FDD)desc = desc + string("Sie sollten aus Sicherheitsgr¸nden das Diskettenlauf-\nwerk entfernen oder zumindest sperren." + '\n');
  if("None" >!< CD)desc = desc + string("Sie sollten aus Sicherheitsgr¸nden das CD-ROM Laufwerk\nentfernen oder zumindest sperren." + '\n');
  if("None" >!< USB)desc = desc + string("Sie sollten aus Sicherheitsgr¸nden den USB Controller\nentfernen oder zumindest im BIOS deaktivieren." + '\n');
  if("FAT" >< FS){
    LD = split(FS, sep:'\n', keep:0);
    for(i=1; i<max_index(LD); i++)
      {
        LDinf = split(LD[i], sep:"|", keep:0);
        if(LDinf !=NULL)
        {
          if("FAT" >< LDinf[1]) LDdesc = LDdesc + "Laufwerksbuchstabe: " + LDinf[0] + ', Dateisystem: ' + LDinf[1] + ', ';
         }
      }
    desc = desc + string("Folgende Logischen Laufwerke sind nicht\nNFTS-formatiert: " + '\n' + LDdesc + '\n');
  }
	desc += 'Pr¸fen Sie zudem, ob bei UEFI-basierten Ger‰ten UEFI Secure Boot aktiviert ist.\n';
}else if("FAT" >!< FS && "None" >< FDD && "None" >< CD && "None" >< USB && "False" >< BOOTINI){
  result = string("erf¸llt");
  desc = string("Ihr System entspricht der Maﬂnahme M4.049.\nPr¸fen Sie zudem, ob bei UEFI-basierten Ger‰ten UEFI Secure Boot aktiviert ist.");
}

set_kb_item(name:"GSHB/M4_049/result", value:result);
set_kb_item(name:"GSHB/M4_049/desc", value:desc);
set_kb_item(name:"GSHB/M4_049/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_049');

exit(0);
