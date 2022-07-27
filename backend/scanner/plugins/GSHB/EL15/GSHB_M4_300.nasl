###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_300.nasl 10646 2018-07-27 07:00:22Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 4.300
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
  script_oid("1.3.6.1.4.1.25623.1.0.94229");
  script_version("$Revision: 10646 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IT-Grundschutz M4.300: Informationsschutz bei Druckern, Kopierern und Multifunktionsger‰ten");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04300.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15");
  script_dependencies("GSHB/GSHB_Printer_SSL-TLS.nasl");

  script_tag(name:"summary", value:"IT-Grundschutz M4.300: Informationsschutz bei Druckern, Kopierern und Multifunktionsger‰ten

  Stand: 14. Erg‰nzungslieferung (14. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M4.300: Informationsschutz bei Druckern, Kopierern und Multifunktionsger‰ten\n';

gshbm =  "IT-Grundschutz M4.300: ";

Printer = get_kb_item("GSHB/Printer");
IPPCert = get_kb_item("GSHB/IPP-Cert");

if(Printer >< "False"){
  result = string("nicht zutreffend");
  desc = string("Das Zielsystem ist kein Drucker oder IPP-Printserver\nund kann nicht getestet werden");
}else if(Printer >< "True"){
  result = string("nicht erf¸llt");
  desc = string('Das Zielsystem ist ein Drucker ohne IPP, so das\nTLS/SSL nicht konfiguriert werden kann. Sie sollten\neinen IPP-Printserver aufsetzen.');
}else if(Printer >< "IPP"){
    if (IPPCert == "none"){
      result = string("nicht erf¸llt");
      desc = string('Das Zielsystem ist ein Drucker oder Printserver mit\nIPP. Anscheindend wurde TLS/SSL nicht konfiguriert,\nso dasss keine verschl¸sselte Daten¸bertragung statt-\nfinden konnte. Sie sollten TLS/SSL aktivieren.');

    }else if(IPPCert >!< "error"){
      result = string("erf¸llt");
      desc = string('Das Zielsystem ist ein Drucker oder Printserver mit\nIPP. Folgende TLS/SSL-Zertifikatsdaten sind\nhinterlegt:\n' + IPPCert);
    }else{
      result = string("Fehler");
      desc = string('Beim Auslesen des TLS/SSL-Zertifikates trat ein\nFehler auf.');

    }
}

set_kb_item(name:"GSHB/M4_300/result", value:result);
set_kb_item(name:"GSHB/M4_300/desc", value:desc);
set_kb_item(name:"GSHB/M4_300/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_300');

exit(0);
