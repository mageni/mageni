# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146701");
  script_version("2021-09-14T08:18:57+0000");
  script_tag(name:"last_modification", value:"2021-09-14 10:28:52 +0000 (Tue, 14 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-13 11:59:41 +0000 (Mon, 13 Sep 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("EFI Fiery Detection Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of EFI Fiery.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdescr_detect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default: 161);

sysdesc = snmp_get_sysdescr(port: port);
if (!sysdesc)
  exit(0);

# Fiery PRO80 80C-KM
# Fiery X3eTY 50_45C-KM
if (sysdesc =~ "^Fiery ") {
  model = "unknown";
  version = "unknown";

  set_kb_item(name: "efi/fiery/detected", value: TRUE);
  set_kb_item(name: "efi/fiery/snmp/detected", value: TRUE);
  set_kb_item(name: "efi/fiery/snmp/port", value: port);
  set_kb_item(name: "efi/fiery/snmp/" + port + "/concluded", value: sysdesc);

  set_kb_item(name: "efi/fiery/snmp/" + port + "/model", value: model);
  set_kb_item(name: "efi/fiery/snmp/" + port + "/version", value: version);
}

exit(0);
