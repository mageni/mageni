###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_033.nasl 10623 2018-07-25 15:14:01Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 4.033
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
  script_oid("1.3.6.1.4.1.25623.1.0.94199");
  script_version("$Revision: 10623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("IT-Grundschutz M4.033: Einsatz eines Viren-Suchprogramms bei Datentr‰geraustausch und Daten¸bertragung");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04033.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_WMI_Antivir.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_keys("WMI/Antivir");
  script_tag(name:"summary", value:"IT-Grundschutz M4.033: Einsatz eines Viren-Suchprogramms bei Datentr‰geraustausch und Daten¸bertragung.

Stand: 14. Erg‰nzungslieferung (14. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M4.033: Einsatz eines Viren-Suchprogramms bei Datentr‰geraustausch und Daten¸bertragung\n';

gshbm =  "IT-Grundschutz M4.033: ";

WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
Antivir = get_kb_item("WMI/Antivir");
AntivirName = get_kb_item("WMI/Antivir/Name");
#AntivirName = split(AntivirName, sep:"|", keep:0);
AntivirUptoDate = get_kb_item("WMI/Antivir/UptoDate");
if (AntivirUptoDate >!< "None") AntivirUptoDate = split(AntivirUptoDate, sep:"|", keep:0);
AntivirEnable = get_kb_item("WMI/Antivir/Enable");
if (AntivirEnable >!< "None") AntivirEnable = split(AntivirEnable, sep:"|", keep:0);
AntivirState = get_kb_item("WMI/Antivir/State");
if (AntivirState >!< "None") AntivirState = split(AntivirState, sep:"|", keep:0);

log = get_kb_item("WMI/Antivir/log");

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba, dieser Test l‰uft nur auf\nMicrosoft Windows Systemen.");
}else if(Antivir >< "error"){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if(Antivir >< "Server"){
  result = string("nicht zutreffend");
  desc = string("Das System ist ein Server und kann nicht\ngetestet werden.");
}else if(Antivir >< "None"){
  result = string("nicht erf¸llt");
  desc = string("Auf dem System wurde kein Antivirenprogramm gefunden.");
}else if(Antivir >< "Server"){
  result = string("nicht zutreffend");
  desc = string("Das System ist ein Server und kann nicht\ngetestet werden.");
}else if(Antivir >< "Windows XP <= SP1"){
  result = string("nicht zutreffend");
  desc = string("Das System ist ein Windows XP System kleiner oder\ngleich Service Pack 1 und kann nicht getestet werden.");
}else if(AntivirName >!< "None" && AntivirState >< "None"){
    if ("True" >< AntivirEnable[2] && "True" >< AntivirUptoDate[2]){
      result = string("erf¸llt");
      desc = string("Das System hat einen Virenscanner installiert, welcher\nl‰uft und aktuell ist.");
    }else if ("True" >< AntivirEnable[2] && "False" >< AntivirUptoDate[2]){
      result = string("nicht erf¸llt");
      desc = string("Das System hat einen Virenscanner installiert, welcher\nl‰uft aber veraltet ist.");
    }else if ("False" >< AntivirEnable[2] && "True" >< AntivirUptoDate[2]){
      result = string("nicht erf¸llt");
      desc = string("Das System hat einen Virenscanner installiert, welcher\nausgeschaltet aber aktuell ist.");
    }else if ("False" >< AntivirEnable[2] && "False" >< AntivirUptoDate[2]){
      result = string("nicht erf¸llt");
      desc = string("Das System hat einen Virenscanner installiert, welcher\nausgeschaltet und veraltet ist.");
    }
}else if(AntivirName >!< "None" && AntivirState >!< "None"){
    if ("266240" >< AntivirState[2]){
      result = string("erf¸llt");
      desc = string("Das System hat einen Virenscanner installiert, welcher\nl‰uft und aktuell ist.");
    }else if ("266256" >< AntivirState[2]){
      result = string("nicht erf¸llt");
      desc = string("Das System hat einen Virenscanner installiert, welcher\nl‰uft aber veraltet ist.");
    }else if ("262144"  >< AntivirState[2] || "270336" >< AntivirState[2]){
      result = string("nicht erf¸llt");
      desc = string("Das System hat einen Virenscanner installiert, welcher\nausgeschaltet aber aktuell ist.");
    }else if ("262160"  >< AntivirState[2] || "270352" >< AntivirState[2]){
      result = string("nicht erf¸llt");
      desc = string("Das System hat einen Virenscanner installiert, welcher\nausgeschaltet und veraltet ist.");
    }
}

set_kb_item(name:"GSHB/M4_033/result", value:result);
set_kb_item(name:"GSHB/M4_033/desc", value:desc);
set_kb_item(name:"GSHB/M4_033/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_033');

exit(0);
