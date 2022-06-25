###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_066.nasl 10646 2018-07-27 07:00:22Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 5.066
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
  script_oid("1.3.6.1.4.1.25623.1.0.95067");
  script_version("$Revision: 10646 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_active");
  script_name("IT-Grundschutz M5.066: Clientseitige Verwendung von SSL/TLS");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05066.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15");
  script_dependencies("GSHB/GSHB_test_WebServer_Cert.nasl");

  script_tag(name:"summary", value:"IT-Grundschutz M5.066: Clientseitige Verwendung von SSL/TLS.

  Stand: 14. Erg‰nzungslieferung (14. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M5.066: Clientseitige Verwendung von SSL/TLS\n';

cert = get_kb_item("GSHB/SSL-Cert");
RootCert = get_kb_item("GSHB/SSL-Cert/RootPEMstate");
sslport = get_kb_item("Ports/tcp/443");

gshbm = "GSHB Maﬂnahme 5.066: ";


if(!sslport){
  result = string("nicht zutreffend");
  desc = string("Auf dem System wurde kein SSL-Port gefunden.");
} else if(cert >< "unknown"){
  result = string("Fehler");
  desc = string("Beim Auslesen des SSL-Zertifikates\nwurde ein Fehler festgestellt.");
} else if("Verify return code: 0 (ok)" >< cert){
  result = string("unvollst‰ndig");
  certpart =  split(cert, sep:'\n', keep:0);
  desc = string('Folgendes Zertifikat auf dem Zielsystem wurde erfolgreiche\nverifiziert:\n' + certpart[0] + '\nWeitere Tests sind zurzeit nicht mˆglich.');
} else{
  result = string("nicht erf¸llt");
  certpart =  split(cert, sep:'\n', keep:0);
  desc = string('Beim Verifizieren dieses SSL-Zertifikates:\n' + certpart[0] + '\nist folgendes Problem aufgetreten:\n' + certpart[1]);
  if (RootCert == "FAIL") desc += string('\nSpeichern Sie ggf. f¸r den Test "Test Webserver SSL\nCertificate" unter "Network Vulnerability Test Preferences"\nein Root Zertifikat.');
}

set_kb_item(name:"GSHB/M5_066/result", value:result);
set_kb_item(name:"GSHB/M5_066/desc", value:desc);
set_kb_item(name:"GSHB/M5_066/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M5_066');

exit(0);
