###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_syncrify_server_detect.nasl 10911 2018-08-10 15:16:34Z cfischer $
#
# Syncrify Server Remote Version Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805550");
  script_version("$Revision: 10911 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:16:34 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-05-11 18:53:08 +0530 (Mon, 11 May 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Syncrify Server Remote Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Syncrify Server.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 5800);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

serPort = get_http_port(default:5800);
rcvRes = http_get_cache(item: "/app", port:serPort);

if(rcvRes && rcvRes =~ ">Powered by.*>Syncrify")
{
  Version = eregmatch(pattern:"Syncrify.*Version..([0-9.]+).-.build.([0-9.]+)", string:rcvRes);
  if(Version[1])
  {
    serVer = Version[1];
    set_kb_item(name:"syncrify/" + serPort + "/version",value:serVer);
    set_kb_item(name:"syncrify/installed",value:TRUE);
    buildVer = Version[2];
    if(buildVer){
      set_kb_item(name:"syncrify/" + serPort + "/build",value:buildVer);
    }

    ## CPE currently not available, Need to update once available.
    cpe = build_cpe(value:serVer, exp:"^([0-9.]+)", base:"cpe:/a:syncrify:server:");
    if(isnull(cpe))
      cpe = "cpe:/a:syncrify:server";

    register_product(cpe:cpe, location:"/", port:serPort);

    log_message(data: build_detection_report(app:"Syncrify Server",
                                             version:serVer + ' Build: ' + buildVer,
                                             install:"/",
                                             cpe:cpe,
                                             concluded: Version[0]),
    port:serPort);
  }
}
