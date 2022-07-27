###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cscart_detect.nasl 10905 2018-08-10 14:32:11Z cfischer $
#
# CS-Cart Detection
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106397");
  script_version("$Revision: 10905 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:32:11 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-11-18 10:07:02 +0700 (Fri, 18 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("CS-Cart Detection");

  script_tag(name:"summary", value:"Detection of CS-Cart

  The script sends a connection request to the server and attempts to detect the presence of CS-Cart
and to extract its version");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.cs-cart.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

if (!can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/cart", "/cs", "/store", "/cscart", "/cs-cart", cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/");

  if ("CS-Cart - Shopping Cart Software" >< res && "index.php?dispatch=" >< res) {
    version = "unknown";

    vers = eregmatch(pattern: "\.js\?ver=([0-9.]+)", string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      set_kb_item(name: "cs_cart/version", value: version);
    }
    else {
      req = http_get(port: port, item: dir + "/changelog.txt");
      res = http_keepalive_send_recv(port: port, data: req);

      vers = eregmatch(pattern: "Version ([0-9.]+(\.?([a-zA-Z0-9]+))?),", string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        set_kb_item(name: "cs_cart/version", value: version);
      }
    }

    set_kb_item(name: "cs_cart/installed", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:cs-cart:cs-cart:");
    if (!cpe)
      cpe = 'cpe:/a:cs-cart:cs-cart';

    register_product(cpe: cpe, location: install, port: port);

    log_message(data: build_detection_report(app: "CS-Cart", version: version, install: install, cpe: cpe,
                                             concluded: vers[0]),
                port: port);
  }
}

exit(0);
