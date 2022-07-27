###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_liferay_detect.nasl 11418 2018-09-17 05:57:41Z cfischer $
#
# Liferay Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.808730");
  script_version("$Revision: 11418 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 07:57:41 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-08-01 13:52:04 +0530 (Mon, 01 Aug 2016)");
  script_name("Liferay Version Detection");
  script_tag(name:"summary", value:"Detects the installed version of
  Liferay.

  This script sends HTTP GET request and try to ensure the presence of Liferay
  from the response.");

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

life_port = get_http_port(default:8080);

foreach dir(make_list_unique("/", "/Liferay", cgi_dirs(port:life_port)))
{

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + '/web/guest';

  sndReq = http_get(item:url, port:life_port);
  rcvRes = http_send_recv(port:life_port, data:sndReq);

  if(rcvRes =~ "^HTTP/1\.[01] 200" && "Liferay<" >< rcvRes &&
     rcvRes =~ "Powered By.*Liferay" && "> Email Address" ><rcvRes)
  {
    vers = eregmatch(pattern:"Liferay Portal Community Edition (([0-9.]+) ?([A-Z0-9]+)? ([A-Z0-9]+))", string:rcvRes);
    if(vers[1]){
      version = vers[1];
    }
    else{
      version ="Unknown";
    }

    version = ereg_replace( pattern:" ", replace:".", string:version);

    set_kb_item(name:"www/" + life_port + "/Liferay", value:version);
    set_kb_item(name:"Liferay/Installed", value:TRUE);

    cpe = build_cpe(value:version, exp:"([0-9.A-Z]+)", base:"cpe:/a:liferay:liferay_portal:");
    if(!cpe)
      cpe= "cpe:/a:liferay:liferay_portal";

    register_product(cpe:cpe, location:install, port:life_port);

    log_message(data:build_detection_report(app:"Liferay",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:version),
                                            port:life_port);
    exit(0);
  }
}
exit(0);
