###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_service_desk_remote_detect.nasl 11408 2018-09-15 11:35:21Z cfischer $
#
# Novell Service Desk Remote Version Detection
#
# Authors:
# Rinu Kuriaksoe <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807537");
  script_version("$Revision: 11408 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 13:35:21 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-04-12 10:34:57 +0530 (Tue, 12 Apr 2016)");
  script_name("Novell Service Desk Remote Version Detection");

  script_tag(name:"summary", value:"Detection of installed version
  of Novell Service Desk.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

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

novPort = get_http_port(default:80);

foreach dir (make_list_unique("/", "/novell", "/novell-service-desk", cgi_dirs(port:novPort)))
{
  install = dir;
  if( dir == "/" ) dir = "";

  sndReq = http_get(item:string(dir, "/LiveTime/WebObjects/LiveTime.woa"), port:novPort);
  rcvRes = http_send_recv(port:novPort, data:sndReq);

  if('Licensee: Novell' >< rcvRes &&
     rcvRes =~ 'content=".*Service Management and Service Desk' &&
     'username' >< rcvRes && 'password' >< rcvRes)
  {
    version = eregmatch(pattern:'>Version #([0-9.]+)', string:rcvRes);
    if(version[1]){
      novellVer = version[1];
    }
    else{
      novellVer = "Unknown";
    }

    set_kb_item(name:"Novell/Service/Desk/Installed", value:TRUE);

    cpe = build_cpe(value:novellVer, exp:"^([0-9.]+)", base:"cpe:/a:novell:service_desk:");
    if(!cpe)
      cpe= "cpe:/a:novell:service_desk";

    register_product(cpe:cpe, location:install, port:novPort);

    log_message(data: build_detection_report(app: "Novell Service Desk",
                                             version: novellVer,
                                             install: install,
                                             cpe: cpe,
                                             concluded: novellVer),
                                             port: novPort);

  }
}
