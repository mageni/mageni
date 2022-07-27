# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.142806");
  script_version("2019-08-28T07:11:15+0000");
  script_tag(name:"last_modification", value:"2019-08-28 07:11:15 +0000 (Wed, 28 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-27 08:44:37 +0000 (Tue, 27 Aug 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("RICOH Printer Detection (SNMP)");

  script_tag(name:"summary", value:"This script performs SNMP based detection of RICOH printer devices.");

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

# RICOH MP 3053 1.16 / RICOH Network Printer C model / RICOH Network Scanner C model / RICOH Network Facsimile C model
# RICOH Aficio MP 201 1.04 / RICOH Network Printer C model / RICOH Network Scanner C model / RICOH Network Facsimile C model
# RICOH SP C252DN V1.02 / RICOH Network Printer C model
if (sysdesc =~ "^RICOH" && "RICOH Network Printer" >< sysdesc) {
  set_kb_item(name: 'ricoh_printer/detected', value: TRUE);
  set_kb_item(name: 'ricoh_printer/snmp/detected', value: TRUE);
  set_kb_item(name: 'ricoh_printer/snmp/port', value: port);
  set_kb_item(name: 'ricoh_printer/snmp/' + port + '/concluded', value: sysdesc );

  vers = eregmatch(pattern: "RICOH ((Aficio )?[A-Z]+ [^ ]+) V?([0-9.]+)", string: sysdesc);
  if (!isnull(vers[1]))
    set_kb_item(name: 'ricoh_printer/snmp/' + port + '/model', value: vers[1]);

  if (!isnull(vers[3]))
    set_kb_item(name: 'ricoh_printer/snmp/' + port + '/fw_version', value: vers[3]);
}

exit(0);
