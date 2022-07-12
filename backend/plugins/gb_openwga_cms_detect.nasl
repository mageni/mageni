###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openwga_cms_detect.nasl 11408 2018-09-15 11:35:21Z cfischer $
#
# OpenWGA Content Management Server Version Detection
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807686");
  script_version("$Revision: 11408 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 13:35:21 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-05-03 17:32:47 +0530 (Tue, 03 May 2016)");
  script_name("OpenWGA Content Management Server Version Detection");

  script_tag(name:"summary", value:"Detection of installed version
  of OpenWGA Content Management Server.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

wgaPort = get_http_port(default:8080);

url = "/plugin-management/html/homepage:main.int.html";

sndReq = http_get(item:url, port:wgaPort);
rcvRes = http_send_recv(port:wgaPort, data:sndReq);

if(rcvRes && rcvRes =~ "OpenWG.*Server" &&
  "4f70656e574741e284a220536572766572" >< hexstr(rcvRes) &&
  ">Web Content & Application Development Platform<" >< rcvRes)
{

  install = "/";

  version = eregmatch(pattern:'OpenWG.*Server ([0-9.]+) Maintenance Release .*Build ([0-9.]+)', string:rcvRes);
  if(version[1] && version[2]){
    wgaVer = version[1] + "." + version[2];
  } else{
    wgaVer = "Unknown";
  }

  set_kb_item(name:"OpenWGA/Installed", value:TRUE);

  cpe = build_cpe(value:wgaVer, exp:"^([0-9.]+)", base:"cpe:/a:OpenWGA_CMS:openwga:");
  if(!cpe)
    cpe= "cpe:/a:OpenWGA_CMS:openwga";

  register_product(cpe:cpe, location:install, port:wgaPort);

  log_message(data: build_detection_report(app: "OpenWGA Content Manager",
                                           version: wgaVer,
                                           install: install,
                                           cpe: cpe,
                                           concluded: wgaVer),
                                           port: wgaPort);
}
