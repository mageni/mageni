# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900608");
  script_version("2022-08-15T10:52:44+0000");
  script_tag(name:"last_modification", value:"2022-08-15 10:52:44 +0000 (Mon, 15 Aug 2022)");
  script_tag(name:"creation_date", value:"2009-03-12 10:50:11 +0100 (Thu, 12 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Progress WS_FTP Server Detection (FTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/ws_ftp/detected");

  script_tag(name:"summary", value:"FTP based detection of Progress WS_FTP Server.");

  exit(0);
}

include("host_details.inc");
include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default: 21);

banner = ftp_get_banner(port: port);

# 220 example.com X2 WS_FTP Server 8.7.0(51275849) FIPS
# 220 ftp.unionleasing.com X2 WS_FTP Server 7.5.1(86175423)
if (! banner || "WS_FTP Server" >!< banner)
  exit(0);

version = "unknown";

set_kb_item(name: "progress/ws_ftp/server/detected", value: TRUE);
set_kb_item(name: "progress/ws_ftp/server/ftp/detected", value: TRUE);
set_kb_item(name: "progress/ws_ftp/server/ftp/port", value: port);
set_kb_item(name: "progress/ws_ftp/server/ftp/" + port + "/concluded", value: banner);

vers = eregmatch(pattern: "WS_FTP Server ([0-9.]+)", string: banner);
if (!isnull(vers[1]))
  version = vers[1];

set_kb_item(name: "progress/ws_ftp/server/ftp/" + port + "/version", value: version);

exit(0);
