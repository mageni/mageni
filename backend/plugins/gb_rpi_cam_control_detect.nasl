###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rpi_cam_control_detect.nasl 10905 2018-08-10 14:32:11Z cfischer $
#
# RPi Cam Control Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.812361");
  script_version("$Revision: 10905 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:32:11 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-12-26 12:43:03 +0530 (Tue, 26 Dec 2017)");
  script_name("RPi Cam Control Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  RPi Cam Control.

  This script sends HTTP GET request and try to ensure the presence of
  RPi Cam Control");

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
include("cpe.inc");

ripPort = get_http_port(default:80);

rcvRes = http_get_cache(port:ripPort, item:"/");
if('<title>RPi Cam Control' >< rcvRes)
{
  version = "unknown";

  ripVer = eregmatch(pattern:">RPi Cam Control v([0-9.]+):", string:rcvRes);
  if(ripVer[1]){
    version = ripVer[1];
  }

  set_kb_item(name:"RPi/Cam/Control/Installed", value:TRUE);

  cpe = build_cpe(value:version, exp:"([0-9.]+)", base:"cpe:/a:rpi:cam_control:");
  if(!cpe){
    cpe= "cpe:/a:rpi:cam_control";
  }

  register_product(cpe:cpe, location:"/", port:ripPort);

  log_message(data: build_detection_report( app:"RPi Cam Control",
                                            version:version,
                                            install:"/",
                                            cpe:cpe,
                                            concluded:ripVer),
                                            port:ripPort);
}

exit(0);
