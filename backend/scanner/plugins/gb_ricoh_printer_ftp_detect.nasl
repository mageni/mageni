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
  script_oid("1.3.6.1.4.1.25623.1.0.142809");
  script_version("2019-08-29T10:39:20+0000");
  script_tag(name:"last_modification", value:"2019-08-29 10:39:20 +0000 (Thu, 29 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-28 04:15:03 +0000 (Wed, 28 Aug 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("RICOH Printer Detection (FTP)");

  script_tag(name:"summary", value:"This script performs FTP based detection of RICOH printer devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/ricoh/printer/detected");

  exit(0);
}

include("ftp_func.inc");

port = get_ftp_port(default: 21);
banner = get_ftp_banner(port: port);

# 220 RICOH MP 3053 FTP server (12.76.1) ready.
# 220 RICOH SP C250DN (d9e0d4) FTP server ready
# 220 RICOH Aficio MP C3000 FTP server (5.20.1) ready.
# n.b. This is the Network Interface Board (NIB) version and not the firmware version
if (banner && "RICOH" >< banner && "FTP server" >< banner) {
  set_kb_item(name: 'ricoh_printer/detected', value: TRUE);
  set_kb_item(name: 'ricoh_printer/ftp/detected', value: TRUE);
  set_kb_item(name: 'ricoh_printer/ftp/port', value: port);
  set_kb_item(name: 'ricoh_printer/ftp/' + port + '/concluded', value: banner);

  mod = eregmatch(pattern: "RICOH ((Aficio )?[A-Z]+ [^ ]+)", string: banner);
  if (!isnull(mod[1]))
    set_kb_item(name: 'ricoh_printer/ftp/' + port + '/model', value: mod[1]);
}

exit(0);
