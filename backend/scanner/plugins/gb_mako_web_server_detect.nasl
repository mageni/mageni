###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mako_web_server_detect.nasl 11418 2018-09-17 05:57:41Z cfischer $
#
# Mako Web Server Remote Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811770");
  script_version("$Revision: 11418 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 07:57:41 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-09-18 16:20:30 +0530 (Mon, 18 Sep 2017)");
  script_name("Mako Web Server Remote Detection");
  script_tag(name:"summary", value:"Detects the installed version of
  Mako Web Server.

  This script sends HTTP GET request and try to ensure the presence of
  Mako Web Server from the response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl");
  script_require_ports("Services/www", 9357, 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

makPort = get_http_port(default:9357);
banner = get_http_banner(port:makPort);
if(!banner){
  exit(0);
}

if("Server: MakoServer.net" >< banner)
{
  ##Version info not available
  makVer = "Unknown";

  set_kb_item(name:"Mako/WebServer/installed", value:TRUE);

  ##No CVE Present, creating cve as cpe:/a:mako:mako_web_server
  cpe = "cpe:/a:mako:mako_web_server";

  register_product(cpe:cpe, location:"/", port:makPort);
  log_message(data: build_detection_report(app:"Mako Web Server",
                                           version: makVer,
                                           install:"/",
                                           cpe:cpe,
                                           concluded: "Mako Web Server with version " + makVer),
                                           port:makPort);
  exit(0);
}
exit(0);
