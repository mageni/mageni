# Copyright (C) 2019 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143150");
  script_version("2019-11-20T06:26:35+0000");
  script_tag(name:"last_modification", value:"2019-11-20 06:26:35 +0000 (Wed, 20 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-20 04:03:51 +0000 (Wed, 20 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Tautulli Detection");

  script_tag(name:"summary", value:"Detection of Tautulli.

  The script sends a connection request to the server and attempts to detect Tautulli and extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("CherryPy/banner");
  script_require_ports("Servives/www", 8181);

  script_xref(name:"URL", value:"https://tautulli.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8181);

banner = get_http_banner(port: port);

if ("CherryPy" >!< banner)
  exit(0);

foreach dir (make_list_unique("/", "/tautulli", cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/home";
  res = http_get_cache(port: port, item: url);

  if (res =~ "^HTTP/1\.[01] 303") {
    # Follow 2 redirects (logout/login)
    for (i = 0; i < 2; i++) {
      location = http_extract_location_from_redirect(port: port, data: res);
      if (isnull(location))
        break;

      req = http_get(port: port, item: location);
      res = http_keepalive_send_recv(port: port, data: req);
      if (res !~ "HTTP/1\.[01] 303")
        break;
    }
  }

  if (res =~ "<title>Tautulli - (Home|Login)" && 'content="Tautulli"' >< res) {
    version = "unknown";

    url = dir + "/settings";
    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req);

    # <h3>Version v2.1.38 <small><a id="changelog-modal-link"
    vers = eregmatch(pattern: "Version v([0-9.]+)", string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      concUrl = report_vuln_url(port: port, url: url, url_only: TRUE);
    }

    if ("http_plex_admin" >< res && "http_password" >< res)
      set_kb_item(name: "tautulli/" + port + "/noauth", value: TRUE);

    set_kb_item(name: "tautulli/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:tautulli:tautulli:");
    if (!cpe)
      cpe = "cpe:/a:tautulli:tautulli";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Tautulli", version: version, install: install, cpe: cpe,
                                             concluded: vers[0], concludedUrl: concUrl),
                port: port);
    exit(0);
  }
}

exit(0);
