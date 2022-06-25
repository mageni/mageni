###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_open_enterprise_server_remote_detect.nasl 11408 2018-09-15 11:35:21Z cfischer $
#
# Novell Open Enterprise Server Remote Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.809479");
  script_version("$Revision: 11408 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 13:35:21 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-11-21 13:12:56 +0530 (Mon, 21 Nov 2016)");
  script_name("Novell Open Enterprise Server Remote Version Detection");

  script_tag(name:"summary", value:"Detection of installed version
  of Novell Open Enterprise Server.

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

novellPort = get_http_port(default:80);

foreach dir (make_list_unique("/", "/novell", cgi_dirs(port:novellPort)))
{
  install = dir;
  if( dir == "/" ) dir = "";

  sndReq = http_get(item:string(dir, "/welcome/index.html"), port:novellPort);
  rcvRes = http_send_recv(port:novellPort, data:sndReq);

  if('Novell Open Enterprise Server' >< rcvRes)
  {
    version = eregmatch( pattern:"Novell Open Enterprise Server ([0-9A-Z .]+)", string:rcvRes );

    if(version[1]){
      version[1] = ereg_replace( string:version[1], pattern: " ", replace: "." );
      novellVer = version[1];
    }
    else{
      novellVer = "Unknown";
    }

    set_kb_item(name:"Novell/Open/Enterprise/Server/Installed", value:TRUE);

    cpe = build_cpe(value:novellVer, exp:"^([0-9A-Z.]+)", base:"cpe:/a:novell:open_enterprise_server:");
    if(!cpe)
      cpe= "cpe:/a:novell:open_enterprise_server:";

    register_product(cpe:cpe, location:install, port:novellPort);

    log_message(data: build_detection_report(app: "Novell Open Enterprise Server",
                                             version: novellVer,
                                             install: install,
                                             cpe: cpe,
                                             concluded: novellVer),
                                             port: novellPort);
  }
}
