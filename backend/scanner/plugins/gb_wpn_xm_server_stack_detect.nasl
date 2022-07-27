###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wpn_xm_server_stack_detect.nasl 11408 2018-09-15 11:35:21Z cfischer $
#
# WPN-XM Server Stack Remote Version Detection
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807911");
  script_version("$Revision: 11408 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 13:35:21 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-04-19 13:42:29 +0530 (Tue, 19 Apr 2016)");
  script_name("WPN-XM Server Stack Remote Version Detection");

  script_tag(name:"summary", value:"Detection of installed version
  of WPN-XM Server Stack.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

wpnPort = get_http_port(default:80);

if(!can_host_php(port:wpnPort)){
  exit( 0 );
}

url = "/tools/webinterface/index.php";

sndReq = http_get(item:url,  port:wpnPort);
rcvRes = http_send_recv(port:wpnPort, data:sndReq);

if("3c7469746c653e5750d098" >< hexstr(rcvRes) &&
   rcvRes =~ "-XM Server Stack .*</title>" && ">PHP Info<" >< rcvRes)
{
  install = "/";

  version = eregmatch(pattern:"XM Serverstack.*Version ([0-9.]+)", string:rcvRes);
  if(version[1]){
    wpnVer = version[1];
  }
  else{
    wpnVer = "Unknown";
  }

  set_kb_item(name:"WPN-XM/Installed", value:TRUE);

  cpe = build_cpe(value:wpnVer, exp:"^([0-9.]+)", base:"cpe:/a:wpnxm_server_stack:wpnxm:");
  if(!cpe)
    cpe= "cpe:/a:wpnxm_server_stack:wpnxm";

  register_product(cpe:cpe, location:install, port:wpnPort);

  log_message(data: build_detection_report(app: "WPN-XM Server Stack",
                                           version: wpnVer,
                                           install: install,
                                           cpe: cpe,
                                           concluded: wpnVer),
                                           port: wpnPort);
}
exit(0);
