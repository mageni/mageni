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
  script_oid("1.3.6.1.4.1.25623.1.0.108630");
  script_version("2019-08-29T10:30:15+0000");
  script_tag(name:"last_modification", value:"2019-08-29 10:30:15 +0000 (Thu, 29 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-29 10:01:52 +0000 (Thu, 29 Aug 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("RICOH Printer Detection (PJL)");

  script_tag(name:"summary", value:"This script performs Printer Job Language (PJL) based detection
  of RICOH printer devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("pjl_detect.nasl");
  script_require_udp_ports("Services/hp-pjl", 9100);
  script_mandatory_keys("hp-pjl/banner/available");

  exit(0);
}

port = get_kb_item("hp-pjl/port");

banner = get_kb_item("hp-pjl/" + port + "/banner");
if (!banner || banner !~ "^RICOH ")
  exit(0);

set_kb_item(name: 'ricoh_printer/detected', value: TRUE);
set_kb_item(name: 'ricoh_printer/hp-pjl/detected', value: TRUE);
set_kb_item(name: 'ricoh_printer/hp-pjl/port', value: port);
set_kb_item(name: 'ricoh_printer/hp-pjl/' + port + '/concluded', value: banner );

# RICOH MP C4504
# RICOH Aficio MP 5000
# RICOH Aficio MP C305
# RICOH Aficio MP 3350B
# RICOH Aficio 2022
# RICOH MP C406Z
# RICOH IM C2000
# RICOH MP C3004ex
# RICOH SP 4510SF
# RICOH Pro 8120S
mod = eregmatch(pattern: "^RICOH ((Aficio )?[^ ]+ [^ ]*)", string: banner);
if (!isnull(mod[1]))
  set_kb_item(name: 'ricoh_printer/hp-pjl/' + port + '/model', value: mod[1]);

exit(0);
