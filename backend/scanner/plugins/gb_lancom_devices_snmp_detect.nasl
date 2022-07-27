# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143421");
  script_version("2020-01-31T09:37:51+0000");
  script_tag(name:"last_modification", value:"2020-01-31 09:37:51 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-29 08:31:28 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("LANCOM Device Detection (SNMP)");

  script_tag(name:"summary", value:"Detection of LANCOM devices.

  This script performs SNMP based detection of LANCOM devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
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

# LANCOM 1611+ 8.82.0100 / 28.08.2013 202321800137
# LANCOM 1821 Wireless ADSL (Ann.B) 7.58.0045 / 14.11.2008 071831800131
# nb: The following has a space prepended:
#  LANCOM WLC-4025 8.62.0050 / 07.08.2012 086471800054
if (sysdesc =~ "^ ?LANCOM") {
  set_kb_item(name: "lancom/detected", value: TRUE);
  set_kb_item(name: "lancom/snmp/detected", value: TRUE);
  set_kb_item(name: "lancom/snmp/port", value: port);
  set_kb_item(name: "lancom/snmp/" + port + "/detected", value: TRUE);
  set_kb_item(name: "lancom/snmp/" + port + "/concluded", value: sysdesc);

  model = "unknown";
  version = "unknown";

  buf = eregmatch(pattern: "LANCOM ([^ ]+)([A-Za-z0-9()/ +-]+|[A-Za-z0-9()/ +-.]+\))? ([0-9]+\.[0-9.]+)",
                  string: sysdesc);
  if (!isnull(buf[1]))
    model = buf[1];

  if (!isnull(buf[3]))
    version = buf[3];

  set_kb_item(name: "lancom/snmp/" + port + "/version", value: version);
  set_kb_item(name: "lancom/snmp/" + port + "/model", value: model);
}

exit(0);
