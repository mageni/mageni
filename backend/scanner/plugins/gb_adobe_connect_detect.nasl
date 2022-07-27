###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_connect_detect.nasl 11408 2018-09-15 11:35:21Z cfischer $
#
# Adobe Connect Version Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805661");
  script_version("$Revision: 11408 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 13:35:21 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-06-19 10:58:10 +0530 (Fri, 19 Jun 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe Connect Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Adobe Connect.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

acPort = get_http_port(default:80);

sndReq = http_get(item:string("/system/login"), port:acPort);
rcvRes = http_keepalive_send_recv(port:acPort, data:sndReq);

if("Adobe Connect Central Login" >< rcvRes && rcvRes =~ "Copyright.*Adobe Systems")
{
  acVer = eregmatch(pattern:'class="loginHelp" title="([0-9.]+)', string:rcvRes);
  if(!acVer[1]){
    acVer = "Unknown";
  } else {
    acVer = acVer[1];
  }

  set_kb_item(name:"www/" + acPort + "/", value:acVer);
  set_kb_item(name:"adobe/connect/installed", value:TRUE);

  cpe = build_cpe(value:acVer, exp:"([0-9.]+)", base:"cpe:/a:adobe:connect:");
  if(isnull(cpe))
    cpe = "cpe:/a:adobe:connect";

  register_product(cpe:cpe, location:string("/system/login"), port:acPort);
  log_message(data: build_detection_report(app: "Adobe Connect",
                                           version:acVer,
                                           install:string("/system/login"),
                                           cpe:cpe,
                                           concluded:acVer),
                                           port:acPort);
}
