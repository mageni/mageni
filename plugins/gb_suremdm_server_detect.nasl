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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141987");
  script_version("$Revision: 13597 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 10:55:26 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-12 15:35:57 +0700 (Tue, 12 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SureMDM Server Detection");

  script_tag(name:"summary", value:"Detection of SureMDM Server.

The script sends a connection request to the server and attempts to detect SureMDM Server and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.42gears.com/products/suremdm-home/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default: 443);

if (!can_host_asp(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/suremdm", cgi_dirs(port: port))) {
  install = dir;

  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/console/");

  if ("SureMDM : Login" >< res && "DATABASECHECK" >< res) {
    version = "unknown";

    url = dir + "/console/browserservice.aspx/GetVersions";
    headers = make_array("Content-Type", "application/json; charset=utf-8",
                         "X-Requested-With", "XMLHttpRequest",
                         "ApiKey", "apiKey");
    data = "{}";

    req = http_post_req( port: port, url: url, data: data, add_headers: headers);
    versres = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

    # {"d":{"sv":"2.76","sl":"6.30","sf":"6.08","rv":"20.0","ul":"true","es":"true"}}
    vers = eregmatch(pattern: '"sf":"([0-9.]+)"', string: versres);
    if (!isnull(vers[1])) {
      version = vers[1];
      concUrl = url;
    }

    set_kb_item(name: "suremdm/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:42gears:suremdm:");
    if (!cpe)
      cpe = 'cpe:/a:42gears:suremdm';

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "SureMDM", version: version, install: install, cpe: cpe,
                                             concluded: versres, concludedUrl: concUrl),
                port: port);

    exit(0);
  }
}

exit(0);
