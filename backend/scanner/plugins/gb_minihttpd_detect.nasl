###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_minihttpd_detect.nasl 10899 2018-08-10 13:49:35Z cfischer $
#
# mini_httpd Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140802");
  script_version("$Revision: 10899 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:49:35 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-02-23 11:52:05 +0700 (Fri, 23 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("mini_httpd Detection");

  script_tag(name:"summary", value:"Detection of mini_httpd.

The script sends a connection request to the server and attempts to detect mini_httpd and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("mini_httpd/banner");
  script_require_ports("Services/www", 80, 443);

  script_xref(name:"URL", value:"https://acme.com/software/mini_httpd/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");


port = get_http_port(default: 80);

banner = get_http_banner(port: port);
if ("Server: mini_httpd/" >!< banner)
  exit(0);

version = "unknown";

vers = eregmatch(pattern: "mini_httpd/([0-9.]+)", string: banner);
if (!isnull(vers[1]))
  version = vers[1];

set_kb_item(name: "mini_httpd/installed", value: TRUE);

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:acme:mini_httpd:");
if (!cpe)
  cpe = 'cpe:/a:acme:mini_httpd';

register_product(cpe: cpe, location: "/", port: port);

log_message(data: build_detection_report(app: "mini_httpd", version: version, install: "/", cpe: cpe,
                                         concluded: vers[0]),
            port: port);

exit(0);
