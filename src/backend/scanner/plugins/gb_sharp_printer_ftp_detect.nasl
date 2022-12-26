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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149041");
  script_version("2022-12-20T09:52:38+0000");
  script_tag(name:"last_modification", value:"2022-12-20 09:52:38 +0000 (Tue, 20 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-20 07:34:24 +0000 (Tue, 20 Dec 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SHARP Printer Detection (FTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/sharp/printer/detected");

  script_tag(name:"summary", value:"FTP based detection of SHARP printer devices.");

  exit(0);
}

include("ftp_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default: 21);
banner = ftp_get_banner(port: port);

# 220 SHARP MX-4141N Ver 01.06.00.0f.38 FTP server.
# 220 SHARP MX-C301W Ver 01.05.00.0r.15 FTP server.
# Note: The version seems to be not the firmware version
if (banner && banner =~ "SHARP .*FTP server") {
  model = "unknown";
  fw_version = "unknown";

  set_kb_item(name: "sharp/printer/detected", value: TRUE);
  set_kb_item(name: "sharp/printer/ftp/detected", value: TRUE);
  set_kb_item(name: "sharp/printer/ftp/port", value: port);
  set_kb_item(name: "sharp/printer/ftp/" + port + "/concluded", value: banner);

  mod = eregmatch(pattern: "SHARP ([A-Z]{2}-[0-9A-Z]+)", string: banner);
  if (!isnull(mod[1]))
    model = mod[1];

  set_kb_item(name: "sharp/printer/ftp/" + port + "/model", value: model);
  set_kb_item(name: "sharp/printer/ftp/" + port + "/fw_version", value: fw_version);
}

exit(0);
