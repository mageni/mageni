###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_007.nasl 10646 2018-07-27 07:00:22Z cfischer $
#
# IT-Grundschutz, 14. EL, Maßnahme 4.007
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
  script_oid("1.3.6.1.4.1.25623.1.0.94177");
  script_version("$Revision: 10646 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("IT-Grundschutz M4.007: Änderung voreingestellter Passwörter");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04007.html");
  # ACT_ATTACK because it depends on GSHB_SSH_TELNET_BruteForce.nasl which is in ACT_ATTACK as well.
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15");
  script_dependencies("GSHB/GSHB_SSH_TELNET_BruteForce.nasl");

  script_tag(name:"summary", value:"IT-Grundschutz M4.007: Änderung voreingestellter Passwörter.

  Stand: 14. Ergänzungslieferung (14. EL).

  Hinweis:

  Test wird nur über SSH und Telnet ausgeführt.");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M4.007: Änderung voreingestellter Passwörter\n';

gshbm =  "IT-Grundschutz M4.007: ";

ssh = get_kb_item("GSHB/BRUTEFORCE/SSH");
telnet = get_kb_item("GSHB/BRUTEFORCE/TELNET");

if (ssh == "deactivated"){
  result = string("nicht zutreffend");
  desc = string('Der Test wurde nicht aktiviert. Um diesen Test auszu-\nführen, müssen Sie ihn in den Voreinstellungen unter:\n-SSH and Telnet BruteForce attack- aktivieren.');
}else if (ssh == "nossh" && telnet == "notelnet"){
  result = string("Fehler");
  desc = string('Das System kann nicht getestet werden, da weder per\nSSH noch per Telnet zugegriffen werden kann.');
}else if ((ssh == "ok" && telnet == "ok") || (ssh == "ok" && telnet == "notelnet") || (ssh == "nossh" && telnet == "ok")){
  result = string("erfüllt");
  desc = string('Weder über SSH noch über Telnet konnte man sich mit\neinem Default-User und -Passwort anmelden.');
}else{
  result = string("nicht erfüllt");
  desc = string('Mit folgenden Daten konnte man sich am Ziel anmelden:\n');
  if( ssh != "nossh" && ssh != "ok")desc += string('SSH: ' + ssh + '\n');
  if( telnet != "notelnet" && telnet != "ok")desc += string('Telnet: ' + telnet);
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.');
}


set_kb_item(name:"GSHB/M4_007/result", value:result);
set_kb_item(name:"GSHB/M4_007/desc", value:desc);
set_kb_item(name:"GSHB/M4_007/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_007');

exit(0);
