###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_barracuda_load_balancer_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Barracuda Load Balancer Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106151");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-25 13:42:49 +0700 (Mon, 25 Jul 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Barracuda Load Balancer Detection");

  script_tag(name:"summary", value:"Detection of Barracuda Load Balancer

The script sends a connection request to the server and attempts to detect the presence of Barracuda Load
Balancer and to extract its version");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.barracuda.com/products/loadbalancer");


  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8000);

url = "/cgi-mod/index.cgi";
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

if (egrep(pattern: "<title>Barracuda Load Balancer", string: buf, icase: TRUE)) {
  version = 'unknown';

  vers = eregmatch(string: buf, pattern: "barracuda.css\?v=([0-9.]+)",icase:TRUE);
  if (!isnull(vers[1]))
    version = chomp(vers[1]);

  set_kb_item(name: "barracuda_lb/installed", value: TRUE);
  if (version != "unknown")
    set_kb_item(name: "barracuda_lb/version", value: version);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:barracuda:load_balancer:");
  if (!cpe)
    cpe = "cpe:/a:barracuda:load_balancer";

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Barracuda Load Balancer",
                                           version: version, install: "/", cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
