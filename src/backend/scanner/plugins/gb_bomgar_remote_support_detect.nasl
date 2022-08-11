###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bomgar_remote_support_detect.nasl 49579 2015-06-22 16:42:59Z june$
#
# Bomgar Remote Support Detection
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805199");
  script_version("$Revision: 10888 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:08:02 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-06-22 16:44:50 +0530 (Mon, 22 Jun 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Bomgar Remote Support Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Bomgar Remote Support.

  This script sends HTTP GET request and try to confirm the application from
  the response, get the version and sets the result in KB.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

http_port = get_http_port(default:80);

foreach dir (make_list_unique("/", "/bomgar", cgi_dirs(port:http_port)))
{

  rep_dir = dir;
  if (dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/"), port:http_port);

  if("Bomgar Corporation" >< rcvRes && "Support Portal" >< rcvRes)
  {
    bomgarVer = eregmatch(pattern:"Version: ([0-9.]+)", string:rcvRes);
    if(bomgarVer[1]){
      version = bomgarVer[1];
    } else {
      version = "Unknown";
    }

    set_kb_item(name:"Bomgar/installed",value:TRUE);

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:bomgar:remote_support:");
    if(isnull(cpe))
      cpe = "cpe:/a:bomgar:remote_support";

    register_product(cpe:cpe, location:dir, port:http_port);
    log_message(data: build_detection_report(app:"Bomgar Remote Support",
                                             version:version,
                                             install:rep_dir,
                                             cpe:cpe,
                                             concluded:bomgarVer[0]),
                                             port:http_port);
  }
}

exit(0);