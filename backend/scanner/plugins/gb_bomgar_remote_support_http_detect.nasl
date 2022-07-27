# Copyright (C) 2015 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805199");
  script_version("2022-05-05T09:47:00+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-05-05 10:20:08 +0000 (Thu, 05 May 2022)");
  script_tag(name:"creation_date", value:"2015-06-22 16:44:50 +0530 (Mon, 22 Jun 2015)");

  script_name("Bomgar Remote Support Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Bomgar Remote Support.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:80);

# nb: Only installed on the root dir...
url = "/";
res = http_get_cache(item:url, port:port);
if(!res || res !~ "^HTTP/1\.[01] 200" || "Bomgar Corporation" >!< res || "Support Portal" >!< res)
  exit(0);

version = "unknown";

# <!--Product Version: 14.3.1-->
# <!--Product Version: 14.2.3-->
# <!--Product Version: 14.3.3fips-->
# <!--Product Version: 13.1.2-->
#
# nb: Only products from around 2014-2015 and prior are exposing the version.
#
vers = eregmatch(pattern:"<!--Product Version: ([0-9.]+)", string:res);
if(vers[1])
  version = vers[1];

set_kb_item(name:"bomgar/remote_support/detected", value:TRUE);
set_kb_item(name:"bomgar/remote_support/http/detected", value:TRUE);

cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:bomgar:remote_support:");
if(!cpe)
  cpe = "cpe:/a:bomgar:remote_support";

register_product(cpe:cpe, location:url, port:port, service:"www");
log_message(data:build_detection_report(app:"Bomgar Remote Support",
                                        version:version,
                                        install:url,
                                        cpe:cpe,
                                        concluded:vers[0]),
            port:port);

exit(0);
