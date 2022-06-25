# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.147493");
  script_version("2022-01-24T12:10:11+0000");
  script_tag(name:"last_modification", value:"2022-01-25 11:07:10 +0000 (Tue, 25 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-20 08:31:45 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Canon Printer Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Canon printer devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
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

# e.g.:
# Canon iR1024 /P
# Canon MF240 Series /P
# nb: Case insensitive match (via "=~") is expected / done on purpose
if (sysdesc !~ "^Canon [A-Za-z]")
  exit(0);

model = "unknown";
fw_version = "unknown";

set_kb_item(name: "canon/printer/detected", value: TRUE);
set_kb_item(name: "canon/printer/snmp/detected", value: TRUE);
set_kb_item(name: "canon/printer/snmp/port", value: port);
set_kb_item(name: "canon/printer/snmp/" + port + "/banner", value: sysdesc);

# Canon iR1025 /P
# Canon MF230 Series /P
# Canon iR2006/2206 /P
# Canon imageRUNNER1133 series /P
mod_oid = "1.3.6.1.2.1.25.3.2.1.3.1";
m = snmp_get(port: port, oid: mod_oid);
mod = eregmatch(pattern: "^(Canon )?([^ ]+).*", string: m, icase: TRUE);
if (!isnull(mod[2])) {
  model = mod[2];
  set_kb_item(name: "canon/printer/snmp/" + port + "/concludedMod", value: mod[0]);
  set_kb_item(name: "canon/printer/snmp/" + port + "/concludedModOID", value: mod_oid);
}

set_kb_item(name: "canon/printer/snmp/" + port + "/model", value: model);
set_kb_item(name: "canon/printer/snmp/" + port + "/fw_version", value: fw_version);

exit(0);
