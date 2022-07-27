###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_appserv_open_project_detect.nasl 14324 2019-03-19 13:31:53Z cfischer $
#
# AppServ Open Project Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802428");
  script_version("$Revision: 14324 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:31:53 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-04-16 13:02:43 +0530 (Mon, 16 Apr 2012)");
  script_name("AppServ Open Project Version Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.appservnetwork.com/?appserv");

  script_tag(name:"summary", value:"Detection of AppServ Open Project, a open source web
  server.

  The script sends a connection request to the web server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)){
  exit(0);
}

rcvRes = http_get_cache(item: "/", port:port);

if("title>AppServ Open Project" >< rcvRes && ">About AppServ" >< rcvRes)
{
  appVer = eregmatch(pattern:"AppServ Version ([0-9.]+)" , string:rcvRes);
  if(appVer[1] != NULL)
  {
    set_kb_item(name:"www/" + port + "/AppServ",value:appVer[1]);

  }
  set_kb_item(name:"AppServ/installed",value:TRUE);

  cpe = build_cpe(value:appVer[1], exp:"^([0-9.]+)",
                    base:" cpe:/a:appserv_open_project:appserv:");
  if(isnull(cpe))
    cpe = 'cpe:/a:appserv_open_project:appserv';

  location = string(port, "/http");
  register_product(cpe:cpe, location:location, port:port);

  log_message(data:'Detected AppServ Open Project version: ' + appVer[1] +
  '\nLocation: ' + location +
  '\nCPE: '+ cpe +
  '\n\nConcluded from version identification result:\n'
  + appVer[max_index(appVer)-1]);
}

exit(0);