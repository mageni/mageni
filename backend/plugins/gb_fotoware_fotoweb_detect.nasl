###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fotoware_fotoweb_detect.nasl 11408 2018-09-15 11:35:21Z cfischer $
#
# Fotoware Fotoweb Remote Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.808278");
  script_version("$Revision: 11408 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 13:35:21 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-08-04 13:00:08 +0530 (Thu, 04 Aug 2016)");
  script_name("Fotoware Fotoweb Remote Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Fotoware Fotoweb.

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
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

fbport = get_http_port(default:80);

foreach dir(make_list_unique("/", "/fotoweb", "/fotoware/fotoweb", cgi_dirs(port:fbport)))
{

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:dir + "/views/login", port:fbport);

  if(rcvRes =~ "HTTP/1.. 200" && '<title>Log in to FotoWeb' >< rcvRes &&
     ('>Username' >< rcvRes || 'Login or Email' >< rcvRes) && '>Password' >< rcvRes)
  {
    version = "unknown";

    ver = eregmatch(pattern:'<title>Log in to FotoWeb ([0-9.]+)</title>', string:rcvRes);
    if(ver[1]) version = ver[1];

    set_kb_item(name:"Fotoware/Fotoweb/Installed", value:TRUE);
    set_kb_item(name:"www/" + fbport + dir, value:version);

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:fotoware:fotoweb:");
    if(!cpe){

      cpe = "cpe:/a:fotoware:fotoweb";
    }

    register_product(cpe:cpe, location:install, port:fbport);

    log_message( data:build_detection_report( app:"Fotoware Fotoweb",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version),
                                              port:fbport);
  }
}

exit(0);
