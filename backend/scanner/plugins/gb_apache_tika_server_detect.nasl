###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tika_server_detect.nasl 11667 2018-09-28 07:49:01Z santu $
#
# Apache Tika Server Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.810251");
  script_version("$Revision: 11667 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 09:49:01 +0200 (Fri, 28 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-12-20 17:03:54 +0530 (Tue, 20 Dec 2016)");
  script_name("Apache Tika Server Version Detection");
  script_tag(name:"summary", value:"Detection of installed version
  of Apache Tika server.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 9998);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

tikaPort = get_http_port(default:9998);

rcvRes = http_get_cache(item: "/", port: tikaPort);

if(rcvRes && rcvRes =~ "<title>Welcome to the Apache Tika.*Server</title>")
{
  ver = eregmatch( pattern:'<title>Welcome to the Apache Tika ([0-9.]+) Server</title>', string:rcvRes );
  if( ver[1] ){
    version = ver[1];
    set_kb_item(name:"Apache/Tika/Server/ver", value:version);
  } else {
    version = "unknown";
  }

  set_kb_item(name:"Apache/Tika/Server/Installed", value:TRUE);

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:apache:tika:");
  if( ! cpe )
    cpe = "cpe:/a:apache:tika";

  register_product(cpe:cpe, location:"/", port:tikaPort);

  log_message(data:build_detection_report(app:"Apache Tika Server",
                                          version:version,
                                          install:"/",
                                          cpe:cpe,
                                          concluded:version),
                                          port:tikaPort);
}
exit(0);
