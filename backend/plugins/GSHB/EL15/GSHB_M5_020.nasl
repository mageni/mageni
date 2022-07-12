###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_020.nasl 10646 2018-07-27 07:00:22Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 5.020
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
  script_oid("1.3.6.1.4.1.25623.1.0.95057");
  script_version("$Revision: 10646 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("IT-Grundschutz M5.020: Einsatz der Sicherheitsmechanismen von rlogin, rsh und rcp");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05020.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15");
  script_dependencies("GSHB/GSHB_SSH_r-tools.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"IT-Grundschutz M5.020: Einsatz der Sicherheitsmechanismen von rlogin, rsh und rcp.

  Stand: 14. Erg‰nzungslieferung (14. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M5.020: Einsatz der Sicherheitsmechanismen von rlogin, rsh und rcp\n';

gshbm =  "IT-Grundschutz M5.020: ";

OSNAME = get_kb_item("WMI/WMI_OSNAME");

rhosts = get_kb_item("GSHB/R-TOOL/rhosts");
hostsequiv = get_kb_item("GSHB/R-TOOL/hostsequiv");
lshostsequiv = get_kb_item("GSHB/R-TOOL/lshostsequiv");
inetdconf = get_kb_item("GSHB/R-TOOL/inetdconf");
rlogind = get_kb_item("GSHB/R-TOOL/rlogind");
rshd = get_kb_item("GSHB/R-TOOL/rshd");
log = get_kb_item("GSHB/R-TOOL/log");

if(OSNAME >!< "none"){
  result = string("nicht zutreffend");
  desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nFolgendes System wurde erkannt:\n' + OSNAME);
}else if(rhosts == "windows") {
    result = string("nicht zutreffend");
    desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nDas System scheint ein Windows-System zu sein.');
}else if(rhosts == "error"){
  result = string("Fehler");
  if(!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if(log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if(rhosts == "not found" && (hostsequiv == "none" || hostsequiv == "noentry") && (lshostsequiv == "none" || lshostsequiv =~ ".......---...root root.*") && (inetdconf == "noentry" || inetdconf == "none") && rlogind == "not found" && rshd == "not found"){
  result = string("erf¸llt");
  desc = string("Das System entspricht der Maﬂnahme 5.020.");
}else if (rhosts != "not found" || (hostsequiv != "noentry" && hostsequiv != "none") || (lshostsequiv != "none" && lshostsequiv !~ ".......---...root root.*")){
  result = string("nicht erf¸llt");
  desc = string('Es muss sichergestellt werden, dass die Dateien\n$HOME/.rhosts und /etc/hosts.equiv nicht vorhanden sind oder\ndass sie leer sind und der Benutzer keine Zugriffsrechte auf\nsie hat.');
   if (rhosts != "not found") desc += string('\nFolgende .rhost Dateien wurden gefunden:\n' + rhosts);
   if (hostsequiv != "none"){
     val = split(lshostsequiv, sep:" ", keep:0);
     desc += string('\nFolgende Zugriffsrechte gelten f¸r -/etc/hosts.equiv- :\n' + val[0] + " " + val[2] + " "+ val[3]);
   }
   if (hostsequiv != "noentry" && hostsequiv != "none")desc += string('\nFolgende Eintr‰ge wurden in  -/etc/hosts.equiv- gefunden:\n' + hostsequiv);

   if ("+" >< hostsequiv) desc += string('\nSollte die Benutzung der Datei -/etc/hosts.equiv- unumg‰nglich\nsein, muss sichergestellt sein, dass kein Eintrag + vorhanden\nist, da hierdurch jeder Rechner vertrauensw¸rdig w¸rde.');

   if (rlogind != "not found" || rshd != "not found"){
     desc += string('\nEs sollte verhindert werden, dass die Daemons rlogind und rshd\ngestartet werden kˆnnen. (siehe hierzu die Datei\n/etc/inetd.conf und Maﬂnahme M 5.16)');
     if (inetdconf != "none" && inetdconf != "noentry")desc += string('\nFolgende Eintr‰ge stehen in Ihrer -/etc/inetd.conf-:\n' + inetdconf);

     else desc += string('\nIhre -/etc/inetd.conf- ist leer.');
   }
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf\nbzw. es konnte kein Ergebnis ermittelt werden.');
}

set_kb_item(name:"GSHB/M5_020/result", value:result);
set_kb_item(name:"GSHB/M5_020/desc", value:desc);
set_kb_item(name:"GSHB/M5_020/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M5_020');

exit(0);
