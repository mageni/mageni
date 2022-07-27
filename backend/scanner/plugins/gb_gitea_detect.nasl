###############################################################################
# OpenVAS Vulnerability Test
#
# Gitea Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.141676");
  script_version("2019-04-25T08:58:41+0000");
  script_tag(name:"last_modification", value:"2019-04-25 08:58:41 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-11-13 11:18:05 +0700 (Tue, 13 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Gitea Detection");

  script_tag(name:"summary", value:"Detection of Gitea.

The script sends a connection request to the server and attempts to detect Gitea and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 3000, 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://gitea.io/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 3000);

res = http_get_cache(port: port, item: "/user/login");

if ("Gitea - Git with a cup of tea" >< res && "i_like_gitea" >< res) {
  version = "unknown";

  # Gitea Version: 1.4.0
  # Gitea Version: 274ff0d
  # Gitea Version: 1.8.0&#43;rc2
  # Gitea Version: 1.8.0-rc2
  vers = eregmatch(pattern: 'Gitea Version: ([^ ]+)', string: res);
  if (!isnull(vers[1])) {
    version = str_replace(string: vers[1], find: "&#43;", replace: ".");
    version = str_replace(string: version, find: "-", replace: ".");
  }

  set_kb_item(name: "gitea/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9a-z.]+)", base: "cpe:/a:gitea:gitea:");
  if (!cpe)
    cpe = 'cpe:/a:gitea:gitea';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Gitea", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);

  goVersion = "unknown";

  goVer = eregmatch(pattern: 'version">Go([0-9.]+)', string: res);
  if (!isnull(goVer[1]))
    goVersion = goVer[1];

  gocpe = build_cpe(value: goVersion, exp: "^([0-9.]+)", base: "cpe:/a:golang:go:");
  if (!gocpe)
    gocpe = 'cpe:/a:golang:go';

  register_product(cpe: gocpe, location: "/", port:port);

  log_message(data: build_detection_report(app: "Go Programming Language", version: goVersion, install: "/",
                                           cpe: gocpe, concluded: goVer[0]),
              port: port);

  exit(0);
}

exit(0);
