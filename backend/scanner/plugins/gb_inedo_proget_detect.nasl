###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_inedo_proget_detect.nasl 11707 2018-10-01 10:08:31Z ckuersteiner $
#
# Inedo ProGet Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.141540");
  script_version("$Revision: 11707 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-01 12:08:31 +0200 (Mon, 01 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-10-01 15:26:45 +0700 (Mon, 01 Oct 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Inedo ProGet Detection");

  script_tag(name:"summary", value:"Detection of Inedo ProGet.

The script sends a connection request to the server and attempts to detect Inedo ProGet and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://inedo.com/proget");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/log-in");

if ("X-ProGet-Version:" >< res && "proget-login-user" >< res) {
  version = "unknown";

  # X-ProGet-Version: 5.0.8.5 (for 5.0.8 Build 5)
  vers = eregmatch(pattern: "X-ProGet-Version: ([0-9.]+)", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "inedo_proget/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:inedo:proget:");
  if (!cpe)
    cpe = 'cpe:/a:inedo:proget';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Inedo ProGet", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
