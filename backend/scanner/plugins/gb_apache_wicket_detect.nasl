###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_wicket_detect.nasl 11408 2018-09-15 11:35:21Z cfischer $
#
# Apache Wicket Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.807584");
  script_version("$Revision: 11408 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 13:35:21 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-05-10 15:16:04 +0530 (Tue, 10 May 2016)");
  script_name("Apache Wicket Version Detection");
  script_tag(name:"summary", value:"Detection of installed version
  of Apache Wicket.

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
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:8080);

foreach dir(make_list_unique("/", "/wicket-examples", "/wicket/wicket-examples", "/apache-wicket", cgi_dirs(port:port)))
{

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item: dir + "/index.html", port:port);

  if( rcvRes =~ "HTTP/1.. 200" &&
      ('<title>Wicket Examples</title>' >< rcvRes) || ('> Wicket' >< rcvRes) ||
      ('mappers">Wicket' >< rcvRes))
  {
    ver = eregmatch( pattern:'class="version"> Wicket Version:.*>([0-9.A-Z-]+)</span>', string:rcvRes );
    if( ver[1] ){
      version = ver[1];
    } else {
      version = "unknown";
    }
    version = ereg_replace(pattern:"-", string:version, replace: ".");

    set_kb_item( name:"Apache/Wicket/Installed", value:TRUE );

    cpe = build_cpe(value:version, exp:"^([0-9.A-Z]+)", base:"cpe:/a:apache:wicket:");
    if( ! cpe )
      cpe = "cpe:/a:apache:wicket";

    register_product(cpe:cpe, location:install, port:port);

    log_message(data:build_detection_report(app:"Apache Wicket",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:version),
                                            port:port);
  }
}
exit(0);
