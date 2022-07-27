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
  script_oid("1.3.6.1.4.1.25623.1.0.142834");
  script_version("2019-09-03T05:31:07+0000");
  script_tag(name:"last_modification", value:"2019-09-03 05:31:07 +0000 (Tue, 03 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-03 01:48:27 +0000 (Tue, 03 Sep 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Lexmark Printer Detection (SNMP)");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Lexmark printer devices.");

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

# Lexmark CX510de version NH61.GM.N634 kernel 3.0.0 All-N-1
# Lexmark XM3250 version MXTGM.052.024 kernel 4.11.12-yocto-standard-75677a77e1bb29a486d543e92014998b All-N-1
# Lexmark XC2235 version CXTZJ.052.024 kernel 4.11.12-yocto-standard-7c6e6fab694c88eb205167072e999ab1 All-N-1
# Note: Nxxxx.xxx.xxx is the network version and not the firmware version
if (sysdesc =~ "^Lexmark") {
  set_kb_item(name: 'lexmark_printer/detected', value: TRUE);
  set_kb_item(name: 'lexmark_printer/snmp/detected', value: TRUE);
  set_kb_item(name: 'lexmark_printer/snmp/port', value: port);
  set_kb_item(name: 'lexmark_printer/snmp/' + port + '/concluded', value: sysdesc );

  model = eregmatch(pattern: "Lexmark ([^ ]+)", string: sysdesc);
  if (!isnull(model[1]))
    set_kb_item(name: 'lexmark_printer/snmp/' + port + '/model', value: model[1]);

  version = eregmatch(pattern: "version ([^ ]+)", string: sysdesc);
  if (!isnull(version[1]) && version[1] !~ "^N")
    set_kb_item(name: 'lexmark_printer/snmp/' + port + '/fw_version', value: version[1]);
}

exit(0);
