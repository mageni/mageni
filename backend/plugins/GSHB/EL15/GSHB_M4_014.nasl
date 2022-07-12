###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_014.nasl 10623 2018-07-25 15:14:01Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 4.014
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
  script_oid("1.3.6.1.4.1.25623.1.0.94181");
  script_version("$Revision: 10623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("IT-Grundschutz M4.014: Obligatorischer Passwortschutz unter Unix");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04014.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_SSH_passwords.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_tag(name:"summary", value:"IT-Grundschutz M4.014: Obligatorischer Passwortschutz unter Unix.

Stand: 14. Erg‰nzungslieferung (14. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M4.014: Obligatorischer Passwortschutz unter Unix\n';

gshbm =  "IT-Grundschutz M4.014: ";

OSVER = get_kb_item("WMI/WMI_OSVER");
SHADOW = get_kb_item("GSHB/etc_shadow");
NoPWUser = get_kb_item("GSHB/NoPWUser");
PWUser = get_kb_item("GSHB/PWUser");
SunPasswd = get_kb_item("GSHB/SunPasswd");
LOG = get_kb_item("GSHB/etc_shadow/log");


Testdays = "180";

if(OSVER >!< "none"){
  OSNAME = get_kb_item("WMI/WMI_OSNAME");
  result = string("nicht zutreffend");
  desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nFolgendes System wurde erkannt:\n' + OSNAME);
}else if(SHADOW == "windows") {
    result = string("nicht zutreffend");
    desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nDas System scheint ein Windows-System zu sein.');
}else if (LOG){
  result = string("Fehler");
  desc = string('Beim Testen des Systems ist ein Fehler aufgetreten:\n' + LOG);
}else if(PWUser != "none" || NoPWUser!= "none"){
  User = split(PWUser, sep:";", keep:0);
  for(i=0; i<max_index(User); i++){
    val = split(User[i], sep:":", keep:0);
    if (int(val[1]) > int(Testdays)) Failuser += '\nUser: ' + val[0] +", zuletzt ge‰ndert vor " + val[1] + " Tagen";
  }
  if (NoPWUser >!< "none" || Failuser){
    result = string("nicht erf¸llt");
    if (NoPWUser >!< "none") desc = string('Beim Testen des Systems wurde festgestellt, dass\nfolgende Benutzer kein Passwort haben:\n' + NoPWUser);
    if (Failuser) desc += string('\nBeim Testen des Systems wurde festgestellt, dass\nfolgende User ihr Passwort seit ¸ber ' + Testdays + "\nTagen nicht ge‰ndert haben:" + Failuser);
  }else if(SunPasswd >< "noperm"){
    result = string("Fehler");
    desc = string('Beim Testen des Systems wurde festgestellt, dass die\nBerechtigung nicht reicht um "passwd -sa" auszuf¸hren.');
  }else{
      result = string("Fehler");
      desc = string("Beim Testen des Systems trat ein unbekannter Fehler auf.");
  }
}else if (SHADOW == "nopermission" && PWUser == "none" && NoPWUser == "none"){
  result = string("unvollst‰ndig");
  desc = string('Beim Testen des Systems wurde festgestellt, dass der\nTestbenutzer keine Berechtigung hat den Befehl passwd\nauszuf¸hren. Alternativ wurde versucht, die Datei\n/etc/shadow zu lesen. Bitte pr¸fen Sie manuell ob die\nUser der Maﬂnahme M4.014 entsprechen.');
}else if (SHADOW == "noshadow" && PWUser == "none" && NoPWUser == "none"){
  result = string("nicht erf¸llt");
  desc = string('Beim Testen des Systems wurde festgestellt, dass die\nDatei /etc/shadow anscheinend nicht vorhanden ist,\nbzw. nicht genutzt wird.');
}


set_kb_item(name:"GSHB/M4_014/result", value:result);
set_kb_item(name:"GSHB/M4_014/desc", value:desc);
set_kb_item(name:"GSHB/M4_014/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_014');

exit(0);
