###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_videoiq_camera_detect.nasl 11328 2018-09-11 12:32:47Z tpassfeld $
#
# VideoIQ Camera Remote Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807357");
  script_version("$Revision: 11328 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-11 14:32:47 +0200 (Tue, 11 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-08-23 15:56:59 +0530 (Tue, 23 Aug 2016)");
  script_name("VideoIQ Camera Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  VideoIQ Camera.

  This script sends HTTP GET request and try to ensure the presence of
  VideoIQ Camera.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");

port = get_http_port(default:80);

url = "/?wicket:bookmarkablePage=:com.videoiq.fusion.camerawebapi.ui.pages.LoginPage";
req = http_get(item:url, port:port);
res = http_send_recv(port:port, data:req);

if('<title>VideoIQ Camera Login</title>' >< res && '>User name' >< res &&
   '>Password' >< res && '>Login' >< res){

  version = "unknown";

  set_kb_item(name:"videoiq/camera/detected", value:TRUE);
  set_kb_item(name:"videoiq/camera/" + port + "/detected", value:TRUE);

  cpe = "cpe:/a:videoiq:videoiq_camera:";

  conclUrl = report_vuln_url(port:port, url:url, url_only:TRUE);

  register_and_report_cpe(app:"VideoIQ Camera",
                          ver:version,
                          base:cpe,
                          expr:"^([0-9.]+)",
                          insloc:"/",
                          regPort:port,
                          conclUrl:conclUrl);
}

exit(0);
