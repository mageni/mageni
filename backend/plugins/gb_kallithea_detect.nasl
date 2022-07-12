###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kallithea_detect.nasl 10896 2018-08-10 13:24:05Z cfischer $
#
# Kallithea Remote Version Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.806612");
  script_version("$Revision: 10896 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:24:05 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-11-06 12:02:52 +0530 (Fri, 06 Nov 2015)");
  script_name("Kallithea Remote Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 5000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  Kallithea.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:5000);

foreach dir(make_list_unique("/", "/kallithea", "/repos/kallithea", cgi_dirs(port:port))) {

  install = dir;
  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/", port:port);

  if(rcvRes =~ 'kallithea-scm.*>Kallithea<' && 'kallithea.css' >< rcvRes &&
      'kallithea-logo' >< rcvRes) {

    version = "unknown";

    if(ver = eregmatch( pattern:'target.*>Kallithea</a> ([0-9.]+)', string:rcvRes)) {
      version = ver[1];
    }

    if(version == "unknown") {
      ver = eregmatch( pattern:"kallithea\.css\?ver\=([0-9.]+)", string:rcvRes);
      version = ver[1];
    }

    set_kb_item(name:"www/" + port + "/Kallithea", value:version);
    set_kb_item(name:"Kallithea/Installed", value:TRUE );

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:kallithea:kallithea:");
    if(!cpe)
      cpe = "cpe:/a:kallithea:kallithea";

    register_product(cpe:cpe, location:install, port:port);

    log_message(data:build_detection_report(app:"Kallithea",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0]),
                                              port:port);
    exit(0);
  }
}
