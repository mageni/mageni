###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wd_sharespace_web_detect.nasl 10902 2018-08-10 14:20:55Z cfischer $
#
# Western Digital ShareSpace WEB GUI Detect
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
  script_oid("1.3.6.1.4.1.25623.1.0.812363");
  script_version("$Revision: 10902 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:20:55 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-12-26 17:43:03 +0530 (Tue, 26 Dec 2017)");
  script_name("Western Digital ShareSpace WEB GUI Detect");

  script_tag(name:"summary", value:"Detects the installed version of
  Western Digital ShareSpace.

  This script sends HTTP GET request and try to ensure the presence of
  Western Digital ShareSpace");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

wdPort = get_http_port(default:80);

rcvRes = http_get_cache(port:wdPort, item:"/");
if(rcvRes =~ "<title>WD ShareSpace.*ShareSpace<" && rcvRes =~ "Copyright.*Western Digital Technologies"
   && ">Login<" >< rcvRes)
{
  version = "Unknown";
  set_kb_item( name:"WD/ShareSpace/detected", value:TRUE);
  cpe = 'cpe:/a:western_digital:sharespace';
  location = "/";

  register_product( cpe:cpe, port:wdPort, location:location);
  log_message( data:build_detection_report( app:"Western Digital ShareSpace",
                                            version:version,
                                            install:location,
                                            cpe:cpe),
                                            port:wdPort);
}

exit(0);
