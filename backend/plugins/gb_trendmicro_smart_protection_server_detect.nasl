###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trendmicro_smart_protection_server_detect.nasl 10911 2018-08-10 15:16:34Z cfischer $
#
# Trend Micro Smart Protection Server Remote Version Detection
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811915");
  script_version("$Revision: 10911 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:16:34 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-10-05 17:44:54 +0530 (Thu, 05 Oct 2017)");
  script_name("Trend Micro Smart Protection Server Remote Version Detection");

  script_tag(name:"summary", value:"Detection of Trend Micro Smart Protection Server.

This script sends HTTP GET request and try to get the version from the response.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 4343);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:4343);

if (!can_host_php(port:port))
  exit(0);

res = http_get_cache(item: "/index.php", port: port);

if('Trend Micro Smart Protection Server' >< res &&
   'Please type your user name and password to access the product console.' >< res) {
  vers = "unknown";

  set_kb_item(name: "trendmicro/SPS/Installed", value: TRUE);

  url = "/help/en_US.UTF-8/Introduction.html";
  req = http_get(item: url, port: port);
  res = http_keepalive_send_recv(port: port, data: req );

  vers = eregmatch(pattern: '<title>Trend Micro.* Smart Protection Server.* ([0-9.]+) Online Help<',
                   string: res);
  if(!isnull(vers[1])) {
    version = vers[1];
    concUrl = url;
  }

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:trendmicro:smart_protection_server:");
  if (!cpe)
    cpe = 'cpe:/a:trendmicro:smart_protection_server';

  register_product(cpe: cpe, location: "/", port: port);
  log_message(data: build_detection_report(app: "Trend Micro Smart Protection Server", version: version,
                                           install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
