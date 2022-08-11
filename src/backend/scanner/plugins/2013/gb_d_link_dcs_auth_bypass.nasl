###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_d_link_dcs_auth_bypass.nasl 12297 2018-11-09 16:00:07Z cfischer $
#
# D-Link DCS Authentication Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103647");
  script_version("$Revision: 12297 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("D-Link DCS Authentication Bypass Vulnerability");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/119902/D-Link-DCS-Cameras-Authentication-Bypass-Command-Execution.html");
  script_xref(name:"URL", value:"http://www.d-link.com");
  script_tag(name:"last_modification", value:"$Date: 2018-11-09 17:00:07 +0100 (Fri, 09 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-01-30 11:53:42 +0100 (Wed, 30 Jan 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("DCS-9/banner");
  script_tag(name:"solution", value:"Updates are available");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"D-Link DCS is prone to an authentication-bypass vulnerability.

Attackers can exploit this issue to bypass authentication and to execute commands
due to a remote information disclosure of the configuration.

Affected devices:

  * D-Link DCS-930L, firmware version 1.04

  * D-Link DCS-932L, firmware version 1.02");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if('realm="DCS-9' >!< banner)exit(0);

url = '/frame/GetConfig';
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if('Content-Transfer-Encoding: binary' >< buf && 'filename="Config.CFG"' >< buf) {

  security_message(port:port);
  exit(0);

}

exit(0);
