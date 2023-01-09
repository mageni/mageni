# Copyright (C) 2017 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.106550");
  script_version("2023-01-04T10:13:11+0000");
  script_tag(name:"last_modification", value:"2023-01-04 10:13:11 +0000 (Wed, 04 Jan 2023)");
  script_tag(name:"creation_date", value:"2017-01-30 10:52:02 +0700 (Mon, 30 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("TrueConf Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of TrueConf.");

  script_xref(name:"URL", value:"https://trueconf.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8443);

url = "/";

res = http_get_cache(port: port, item: url);

if (('content="TrueConf Server of TrueConf"' >< res) ||
    ("TrueConf LLC" >< res && "/downloads/trueconf_client.exe" >< res)) {
  version = "unknown";

  vers = eregmatch(pattern: "/public/css/main.php\?version=([0-9.]+)", string: res);
  if (isnull(vers[1])) {
    found = FALSE;
    # API versions differ and are obtained through different .js files. So we just try to iterate
    # through some known versions (3.x - 4.x).
    for (i = 3; i <= 4; i++) {
      if (found == TRUE)
        break;
      for (j = 0; j <= 9; j++) {
        if (found == TRUE)
          break;

        url = "/api/v" + i + "." + j + "/server?&lang=en";
        req = http_get(port: port, item: url);
        res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

        # "version": "4.5.2.10027",
        # "version": "5.2.6.10025",
        vers = eregmatch(pattern: '"version"\\s*:\\s*"([0-9.]+)",', string: res);
        if (!isnull(vers[1]))
          found = TRUE;
      }
    }
  }

  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  set_kb_item(name: "trueconf/detected", value: TRUE);
  set_kb_item(name: "trueconf/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:trueconf:trueconf:");
  if (!cpe)
    cpe = 'cpe:/a:trueconf:trueconf';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "TrueConf", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
