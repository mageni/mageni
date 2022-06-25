###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_raritan_poweriq_detect.nasl 11021 2018-08-17 07:48:11Z cfischer $
#
# Raritan PowerIQ Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106817");
  script_version("$Revision: 11021 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 09:48:11 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-05-22 10:12:10 +0700 (Mon, 22 May 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Raritan PowerIQ Detection");

  script_tag(name:"summary", value:"Detection of Raritan PowerIQ.

The script sends a connection request to the server and attempts to detect Raritan PowerIQ.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("httpver.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.raritan.com/products/dcim-software/power-iq");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default: 443);

url = '/license/records';
res = http_get_cache(port: port, item: url);

if (egrep(pattern: "^HTTP/.* 302 Found", string: res)) {
  data = "sort=id&dir=ASC";
  req = http_post_req(port: port, url: url, data: data, add_headers: make_array("X-Requested-With",
                                                                              "XMLHttpRequest"));
  res = http_keepalive_send_recv(port: port, data: req);
}

if ('"feature":"Power IQ"' >< res) {
  version = "unknown";

  cpe = 'cpe:/a:raritan:power_iq';

  set_kb_item(name: "raritan_poweriq/detected", value: TRUE);

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Raritan PowerIQ", version: version, install: "/", cpe: cpe));
  exit(0);
}

exit(0);
