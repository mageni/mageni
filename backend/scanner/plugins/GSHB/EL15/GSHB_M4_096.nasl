###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_096.nasl 13688 2019-02-15 10:21:10Z cfischer $
#
# IT-Grundschutz, 14. EL, Maßnahme 4.096
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
  script_oid("1.3.6.1.4.1.25623.1.0.94211");
  script_version("$Revision: 13688 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 11:21:10 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_active");
  script_name("IT-Grundschutz M4.096: Abschaltung von DNS");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04096.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_SSH_dns.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"IT-Grundschutz M4.096: Abschaltung von DNS.

  Stand: 14. Ergänzungslieferung (14. EL).");

  exit(0);
}

include("itg.inc");
include("http_func.inc");

name = 'IT-Grundschutz M4.096: Abschaltung von DNS\n';
gshbm =  "IT-Grundschutz M4.096: ";

OSNAME = get_kb_item("WMI/WMI_OSNAME");

VAL1 = get_kb_item("GSHB/DNSTEST/VAL1");
VAL2 = get_kb_item("GSHB/DNSTEST/VAL2");
VAL3 = get_kb_item("GSHB/DNSTEST/VAL3");
VAL4 = get_kb_item("GSHB/DNSTEST/VAL4");
VAL5 = get_kb_item("GSHB/DNSTEST/VAL5");
log = get_kb_item("GSHB/DNSTEST/log");

www_ports = http_get_ports();
if (www_ports){
  foreach www_port( www_ports ) {
    if (www_port == "80" || www_port == "443" || www_port == "8080" || www_port == "8008"|| www_port == "8088")
      ports += www_port + ", ";
  }
  if (ports){
    ports = ports - "[";
    ports = ports - "]";
  }
}

if (VAL1 == "error" && OSNAME == "none"){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if (!ports){
  result = string("nicht zutreffend");
  desc = string('Das System scheint kein Internetserver zu sein. Es\nwurden bei der Überprüfung nur die Ports 80, 443,\n8008, 8080 und 8088 beachtet.');
}else if (OSNAME != "none"){
  result = string("nicht zutreffend");
  desc = string('Folgendes System wurde erkannt:\n' + OSNAME);
}else if (VAL1 == "TRUE" || VAL2 == "TRUE" || VAL3 == "TRUE" || VAL4 == "TRUE" || VAL5 == "TRUE"){
  result = string("nicht erfüllt");
  desc = string('Das System scheint ein Internetserver zu sein.\nEntgegen der Empfehlung aus Maßnahme 4.096, läuft es\nmit aktiviertem DNS.');
}else{
  result = string("erfüllt");
  desc = string('Das System scheint ein Internetserver zu sein. Wie in\nder Maßnahme 4.096 Empfohlen, läuft es ohne\naktiviertem DNS.');
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.');
}

set_kb_item(name:"GSHB/M4_096/result", value:result);
set_kb_item(name:"GSHB/M4_096/desc", value:desc);
set_kb_item(name:"GSHB/M4_096/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_096');

exit(0);