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
  script_oid("1.3.6.1.4.1.25623.1.0.142904");
  script_version("2019-09-18T06:33:38+0000");
  script_tag(name:"last_modification", value:"2019-09-18 06:33:38 +0000 (Wed, 18 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-18 02:35:46 +0000 (Wed, 18 Sep 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Toshiba Printer Detection (FTP)");

  script_tag(name:"summary", value:"This script performs FTP based detection of Toshiba printer devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/toshiba/printer/detected");

  exit(0);
}

include("ftp_func.inc");

port = get_ftp_port(default: 21);
banner = get_ftp_banner(port: port);

# 220 ET0021B7F5158A TOSHIBA e-STUDIO306CS FTP Server NH6.GM.N632 ready.
# 220 ET0021B7F5864C TOSHIBA e-STUDIO305CS FTP Server NH7.GM.N205 ready.
# Note: NHxx.xx.xxx is the network version and not the firmware version
if (banner && "TOSHIBA " >< banner && " FTP Server" >< banner) {
  set_kb_item(name: 'toshiba_printer/detected', value: TRUE);
  set_kb_item(name: 'toshiba_printer/ftp/detected', value: TRUE);
  set_kb_item(name: 'toshiba_printer/ftp/port', value: port);
  set_kb_item(name: 'toshiba_printer/ftp/' + port + '/concluded', value: banner);

  model = eregmatch(pattern: "TOSHIBA ([^ ]+) FTP", string: banner);
  if (!isnull(model[1]))
    set_kb_item(name: 'toshiba_printer/ftp/' + port + '/model', value: model[1]);
}

exit(0);
