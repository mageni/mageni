###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_coturn_http_detect.nasl 13486 2019-02-06 08:39:14Z cfischer $
#
# coturn Detection (HTTP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.141941");
  script_version("$Revision: 13486 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 09:39:14 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-30 13:34:20 +0700 (Wed, 30 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("coturn Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of coturn.

The script sends a connection request to the server and attempts to detect coturn and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("coturn/banner");
  script_require_ports("Services/www", 80, 443);

  script_xref(name:"URL", value:"https://github.com/coturn/coturn");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");

port = get_http_port(default: 443);
banner = get_http_banner(port: port);
if (!banner || "Server: Coturn" >!< banner)
  exit(0);

version = "unknown";

# Server: Coturn-4.5.0.6 'dan Eider'
vers = eregmatch(pattern: "Coturn-([0-9.]+)", string: banner);
if (!isnull(vers[1]))
  version = vers[1];

set_kb_item(name: "coturn/detected", value: TRUE);

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:coturn:coturn:");
if (!cpe)
  cpe = 'cpe:/a:coturn:coturn';

register_product(cpe: cpe, location: "/", port: port, service: "www");

log_message(data: build_detection_report(app: "coturn", version: version, install: "/", cpe: cpe,
                                         concluded: vers[0]),
            port: port);

exit(0);
