###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manage_engine_desktop_central_detect.nasl 10905 2018-08-10 14:32:11Z cfischer $
#
# ManageEngine Desktop Central MSP Detection
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805717");
  script_version("$Revision: 10905 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:32:11 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-07-08 18:54:23 +0530 (Wed, 08 Jul 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("ManageEngine Desktop Central MSP Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  ManageEngine Desktop Central MSP.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8040);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

mePort = get_http_port(default:8040);

res = http_get_cache(port: mePort, item: "/configurations.do");

if (">ManageEngine Desktop Central" >< res) {
  meVer = "unknown";

  ver = eregmatch(pattern:'id="buildNum" value="([0-9]+)', string:res);
  if (!isnull(ver[1]))
    meVer = ver[1];

#  set_kb_item(name:"www/" + mePort + "/", value:meVer);
  set_kb_item(name:"ManageEngine/Desktop_Central/installed",value:TRUE);

  cpe = build_cpe(value:meVer, exp:"^([0-9]+)", base:"cpe:/a:zohocorp:manageengine_desktop_central:");
  if(!cpe)
    cpe = "cpe:/a:zohocorp:manageengine_desktop_central";

  register_product(cpe:cpe, location:"/", port:mePort);

  log_message(data: build_detection_report(app:"ManageEngine Desktop Central MSP", version:meVer, install:"/",
                                           cpe:cpe,  concluded:ver[0]),
              port:mePort);
  exit(0);
}

exit(0);
