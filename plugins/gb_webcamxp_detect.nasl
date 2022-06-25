###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webcamxp_detect.nasl 13689 2019-02-15 10:41:20Z cfischer $
#
# webcamXP Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800221");
  script_version("$Revision: 13689 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 11:41:20 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-01-09 13:48:55 +0100 (Fri, 09 Jan 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("webcamXP Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the installed webcamXP Version and saves the
  version in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

ports = http_get_ports(default_list:make_list(8080, 80));
foreach port (ports)
{
  banner = get_http_banner( port:port );
  rsp = http_get_cache(item:"/", port:port);
  if(!rsp)
    continue;

  if((rsp =~ "^HTTP/1\.[01] 200" && ( "<title>webcamXP" >< rsp || 'content="webcamXP ' >< rsp)) || "erver: webcamXP" >< banner)
  {
    ver = "unknown";
    webcamVer = eregmatch(pattern:" v([0-9.]+)", string:rsp);
    if(webcamVer[1] != NULL){
      ver = webcamVer[1];
      set_kb_item(name:"WebcamXP/Version", value:ver);
    }

    cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/a:webcamxp:webcamxp:");
    if(isnull(cpe))
      cpe = 'cpe:/a:webcamxp:webcamxp';

    register_product( cpe:cpe, location:port + '/tcp', port:port, service:"www" );

    log_message( data:build_detection_report( app:"webcamXP",
                                              version:ver,
                                              install:port + '/tcp',
                                              cpe:cpe,
                                              concluded:webcamVer[0]),
                                              port:port);
  }
}

exit(0);