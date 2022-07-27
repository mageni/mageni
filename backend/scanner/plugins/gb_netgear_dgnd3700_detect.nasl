###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_dgnd3700_detect.nasl 10601 2018-07-25 08:14:14Z asteins $
#
# NETGEAR DGND3700 Routers Detection
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112334");
  script_version("$Revision: 10601 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 10:14:14 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-25 09:22:12 +0200 (Wed, 25 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NETGEAR DGND3700 Routers Detection");

  script_tag(name:"summary", value:"Detection of NETGEAR DGND3700 Routers.

  The script sends a connection request to the server and attempts to detect the presence of the NETGEAR DGND3700 Router.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

CPE = "cpe:/h:netgear:dgnd3700:";

port = get_http_port(default: 8080);

req = http_get(port: port, item: "/");
res = http_keepalive_send_recv(port: port, data: req);

if('WWW-Authenticate: Basic realm="NETGEAR DGND3700' >< res) {
  set_kb_item(name: "netgear/dgnd3700/detected", value: TRUE);
  set_kb_item(name: "netgear/router/detected", value: TRUE);

  version = "unknown";

  # keeping this in, although the version can only be obtained via authentication right now.
  ver = eregmatch(pattern: "NETGEAR DGN3700v([0-9.+])", string: res);
  if (!isnull(ver[1])) {
    version = ver[1];
    set_kb_item(name: "netgear/dgnd3700/version", value: version);
  }

  register_and_report_cpe(app:"Netgear DGND3700", ver:version, concluded:ver[0], base:CPE, expr:"([^0-9.]+)", insloc:"/", regPort:port);

}

exit(0);
