###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xerox_printer_snmp_detect.nasl 12940 2019-01-04 09:23:20Z ckuersteiner $
#
# Xerox Printer Detection (SNMP)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141825");
  script_version("$Revision: 12940 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-04 10:23:20 +0100 (Fri, 04 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-04 13:53:28 +0700 (Fri, 04 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Xerox Printer Detection (SNMP)");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Xerox Printer.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  exit(0);
}

include("snmp_func.inc");

port = get_snmp_port(default: 161);

sysdesc = get_snmp_sysdesc(port: port);
if (!sysdesc)
  exit(0);

# Xerox AltaLink C8045; SS 100.002.008.05702, ...
# FUJI XEROX DocuPrint CM305 df; ...
if (sysdesc =~ "^(FUJI )?(Xerox|XEROX)") {
  set_kb_item(name: 'xerox_printer/detected', value: TRUE);
  set_kb_item(name: "xerox_printer/snmp/detected", value: TRUE);
  set_kb_item(name: 'xerox_printer/snmp/port', value: port);
  set_kb_item(name: 'xerox_printer/snmp/' + port + '/concluded', value: sysdesc );

  mod = eregmatch(pattern: "(Xerox|FUJI XEROX) ([^;]+)", string: sysdesc);
  if (!isnull(mod[2]))
    set_kb_item(name: 'xerox_printer/snmp/' + port + '/model', value: mod[2]);

  # Xerox AltaLink C8045; SS 100.002.008.05702, NC 100.002.05702.1057305v9, UI 100.002.05702, ME 063.022.000, CC 100.002.05702, DF 007.019.000, FI 010.019.000, FA 003.012.013, CCOS 100.008.05702, NCOS 100.008.05702, SC 013.015.006, SU 100.002.05702
  vers = eregmatch(pattern: "SS ([0-9.]+),", string: sysdesc);
  if (!isnull(vers[1])) {
    set_kb_item(name: "xerox_printer/snmp/" + port + "/fw_version", value: vers[1]);
  }
  else {
    # Xerox WorkCentre 7556 v1 Multifunction System; System Software 061.121.225.14700, ESS 061.125.14620.LL
    vers = eregmatch(pattern: "System Software ([0-9.]+),", string: sysdesc);
    if (!isnull(vers[1])) {
      set_kb_item(name: "xerox_printer/snmp/" + port + "/fw_version", value: vers[1]);
    }
    else {
      # FUJI XEROX DocuPrint CM305 df; Net 16.41,ESS 201210101131,IOT 03.00.05
      # FUJI XEROX ApeosPort-IV C3375 ;ESS1.131.3,IOT 84.14.0,ADF 7.16.0,FAX 1.1.14,BOOT 1.0.54,SJFI3.3.0,SSMI1.20.1
      vers = eregmatch(pattern: "ESS( )?([0-9.]+),", string: sysdesc);
      if (!isnull(vers[2])) {
        set_kb_item(name: "xerox_printer/snmp/" + port + "/fw_version", value: vers[2]);
      }
    }
  }

  exit(0);
}

exit(0);
