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
  script_oid("1.3.6.1.4.1.25623.1.0.142905");
  script_version("2019-09-18T06:33:38+0000");
  script_tag(name:"last_modification", value:"2019-09-18 06:33:38 +0000 (Wed, 18 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-18 02:50:20 +0000 (Wed, 18 Sep 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Toshiba Printer Detection (SNMP)");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Toshiba printer devices.");

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

# TOSHIBA e-STUDIO3555C
# TOSHIBA e-STUDIO7506AC
if (sysdesc =~ "^TOSHIBA e-STUDIO") {
  set_kb_item(name: 'toshiba_printer/detected', value: TRUE);
  set_kb_item(name: 'toshiba_printer/snmp/detected', value: TRUE);
  set_kb_item(name: 'toshiba_printer/snmp/port', value: port);
  set_kb_item(name: 'toshiba_printer/snmp/' + port + '/concluded', value: sysdesc );

  model = eregmatch(pattern: "TOSHIBA ([^ ]+)", string: sysdesc);
  if (!isnull(model[1]))
    set_kb_item(name: 'toshiba_printer/snmp/' + port + '/model', value: model[1]);
}

exit(0);
