###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_small_business_router_http_detect.nasl 13277 2019-01-25 03:25:58Z ckuersteiner $
#
# Cisco Small Business Router Detection (HTTP)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141918");
  script_version("$Revision: 13277 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-25 04:25:58 +0100 (Fri, 25 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-25 09:35:38 +0700 (Fri, 25 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco Small Business Router Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of Cisco Small Business Routers.

The script sends a HTTP(S) connection request to the server and attempts to detect Cisco Small Business Routers.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/solutions/small-business/routers.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

res = http_get_cache(port: port, item: "/");

if ("<title>Router</title>" >< res && "trademarks of Cisco Systems" >< res &&
    'getElementById("nk_login")' >< res) {
  version = "unknown";

  set_kb_item(name: "cisco/smb_router/detected", value: TRUE);
  set_kb_item(name: "cisco/smb_router/http/port", value: port);

  # This is just a detection of the web interface without any model/version detection
  # therefore no product/cpe registration
  log_message(data: build_detection_report(app: "Cisco Small Business Router", version: version, install: "/"),
              port: port);
  exit(0);
}

exit(0);
