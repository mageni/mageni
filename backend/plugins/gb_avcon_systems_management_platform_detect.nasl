# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142871");
  script_version("2019-09-23T11:10:59+0000");
  script_tag(name:"last_modification", value:"2019-09-23 11:10:59 +0000 (Mon, 23 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-23 06:57:55 +0000 (Mon, 23 Sep 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("AVCON6 Systems Management Platform Detection");

  script_tag(name:"summary", value:"Detection of AVCON6 Systems Management Platform.

The script sends a connection request to the server and attempts to detect AVCON6 Systems Management Platform.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.epross.com/product-and-service/video-conference-software");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8080);

res = http_get_cache(port: port, item: "/");

if (res =~ "<title>AVCON6 (enterprise information management system|systems management platform)" &&
    res =~ "AVCON6 [ ]?client download") {
  version = "unknown";

  set_kb_item(name: "avcon_smp/detected", value:  TRUE);

  cpe = "cpe:/a:epross:avcon6_system_management_platform";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "AVCON6 Systems Management Platform", version: version,
                                           install: "/", cpe: cpe),
              port: port);
  exit(0);
}

exit(0);
