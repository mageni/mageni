###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_didiwiki_detect.nasl 11408 2018-09-15 11:35:21Z cfischer $
#
# DidiWiki Remote Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.807527");
  script_version("$Revision: 11408 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 13:35:21 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-04-12 10:34:57 +0530 (Tue, 12 Apr 2016)");
  script_name("DidiWiki Remote Version Detection");

  script_tag(name:"summary", value:"Detection of installed version
  of DidiWiki.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

wikiPort = get_http_port(default:8000);

foreach dir (make_list_unique("/", "/didiwiki", "/wiki", cgi_dirs(port:wikiPort)))
{

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + '/WikiHome';

  rcvRes = http_get_cache(item:url, port:wikiPort);

  if('<title>WikiHome</title>' >< rcvRes && '>DidiWiki' >< rcvRes)
  {
    version = eregmatch(pattern:'DidiWiki, Version: ([0-9.]+)', string:rcvRes);
    if(version[1]){
      wikiVer = version[1];
    } else {
      wikiVer = "Unknown";
    }

    set_kb_item(name:"DidiWiki/Installed", value:TRUE);

    cpe = build_cpe(value:wikiVer, exp:"^([0-9.]+)", base:"cpe:/a:didiwiki_project:didiwiki:");
    if(!cpe)
      cpe= "cpe:/a:didiwiki_project:didiwiki";

    register_product(cpe:cpe, location:install, port:wikiPort);

    log_message(data: build_detection_report(app: "DidiWiki",
                                             version: wikiVer,
                                             install: install,
                                             cpe: cpe,
                                             concluded: wikiVer),
                                             port: wikiPort);

  }
}
