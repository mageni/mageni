###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rundeck_detect.nasl 13453 2019-02-05 06:44:30Z ckuersteiner $
#
# Rundeck Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.141959");
  script_version("$Revision: 13453 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 07:44:30 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-05 11:56:48 +0700 (Tue, 05 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Rundeck Detection");

  script_tag(name:"summary", value:"Detection of Rundeck.

The script sends a connection request to the server and attempts to detect Rundeck and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.rundeck.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/user/login");

if ("Rundeck - Login" >< res && ".nodedetail.server" >< res) {
  version = "unknown";

  # data-version-string="2.10.6-1"
  vers = eregmatch(pattern: 'data-version-string="([0-9.-]+)"', string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "rundeck/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.-]+)", base: "cpe:/a:rundeck:rundeck:");
  if (!cpe)
    cpe = 'cpe:/a:rundeck:rundeck';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Rundeck", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
