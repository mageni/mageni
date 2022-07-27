###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nghttp2_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# nghttp2 Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.106171");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-05 14:02:45 +0700 (Fri, 05 Aug 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("nghttp2 Detection");

  script_tag(name:"summary", value:"Detection of nghttp2 web server

The script sends a connection request to the server and attempts to detect the presence of nghttp2 and
to extract its version");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("nghttpx/banner");

  script_xref(name:"URL", value:"https://nghttp2.org/");


  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");


port = get_http_port(default: 80);
banner = get_http_banner(port: port);

if ("Server: nghttpx" >< banner) {
  version = "unknown";

  vers = eregmatch(pattern: "Server: nghttpx nghttp2\/([0-9.]+)", string: banner);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "nghttp2/detected", value: TRUE);
  if (version != "unknown")
    set_kb_item(name: "nghttp2/version", value: version);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:nghttp2:nghttp2:");
  if (!cpe)
    cpe = 'cpe:/a:nghttp2:nghttp2';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "nghttp2", version: version, install: "/",
                                           cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
