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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106840");
  script_version("2023-02-21T10:09:30+0000");
  script_tag(name:"last_modification", value:"2023-02-21 10:09:30 +0000 (Tue, 21 Feb 2023)");
  script_tag(name:"creation_date", value:"2017-05-31 11:35:51 +0700 (Wed, 31 May 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("TerraMaster NAS Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8181);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of TerraMaster NAS.");

  script_xref(name:"URL", value:"https://www.terra-master.com/global/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 8181);

url = "/tos/index.php?user/login";

res = http_get_cache(port: port, item: url);

# 4.1.x versions have "TerraMaster" and "Tos_Check_Box"
# 4.2.x versions might miss "TerraMaster" and/or "Tos_Check_Box" but always have "<title>TOS</title>"
if (("TerraMaster" >!< res || "Tos_Check_Box" >!< res) && "<title>TOS</title>" >!< res) {
  res = http_get_cache(port: port, item: "/");
  if ("<title>TerraMaster" >!< res || 'name="minuser"' >!< res || 'name="dataError"' >!< res) {
    # 5.x versions
    url = "/tos/";
    res = http_get_cache(port: port, item: url);
    if ("TOS - TerraMaster Operating System" >!< res || "re sorry but TOS5 doesn" >!< res)
      exit(0);
  }
}

version = "unknown";
model = "unknown";
location = "/";

# href="/css/ctools.css?ver=TOS3_S2.0_4.1.06">
vers = eregmatch(pattern: "ver=[^_]+_[^_]+_([0-9.]+)", string: res);
if (isnull(vers[1])) {
  url = "/version";
  res = http_get_cache(port: port, item: url);
  # TOS3_S2.0_4.2.07
  vers = eregmatch(pattern: "[^_]+_[^_]+_([0-9.]+)", string: res);
  if (isnull(vers[1])) {
    url = "/v2/welcome";
    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req);
    if (res =~ "^HTTP/1\.[01] 403") {
      csrf_token = http_get_cookie_from_header(buf: res, pattern: 'X-Csrf-Token=([^;\r\n]+)');
      if (!isnull(csrf_token)) {
        headers = make_array("X-Csrf-Token", csrf_token,
                             "Cookie", "X-Csrf-Token=" + csrf_token);
        req = http_get_req(port: port, url: url, add_headers: headers);
        res = http_keepalive_send_recv(port: port, data: req);
      }
    }
    # "comment2":"5.0.171-00221",
    vers = eregmatch(pattern: '"comment2":"([0-9.-]+)"', string: res);
  }
}

if (!isnull(vers[1])) {
  version = vers[1];
  concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
}

# <div class="two"> <p>F2-210</p>
mod = eregmatch(pattern: '<div class="two">[^<]+<p>([^<]+)</p>', string: res);
if (isnull(mod[1])) {
  # "comment1":"F5-221",
  mod = eregmatch(pattern: '"comment1":"([^"]+)"', string: res);
}

if (!isnull(mod[1])) {
  model = mod[1];
  set_kb_item(name: "terramaster/nas/model", value: model);
}

set_kb_item(name: "terramaster/nas/detected", value: TRUE);
set_kb_item(name: "terramaster/nas/http/detected", value: TRUE);

if (model != "unknown") {
  os_name = "TerraMaster " + model + " Firmware";
  hw_name = "TerraMaster " + model;

  os_cpe = build_cpe(value: version, exp: "^([0-9.]+)",
                     base: "cpe:/o:terra-master:" + tolower(model) + "_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:terra-master:" + tolower(model) + "_firmware";

  hw_cpe = "cpe:/h:terra-master:" + tolower(model);
} else {
  os_name = "TerraMaster NAS Firmware";
  hw_name = "TerraMaster NAS Unknown Model";

  os_cpe = build_cpe(value: version, exp: "^([0-9.-]+)", base: "cpe:/o:terra-master:nas_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:terra-master:nas_firmware";

  hw_cpe = "cpe:/h:terra-master:nas";
}

os_register_and_report(os: os_name , cpe: os_cpe, port: port, desc: "TerraMaster NAS Detection (HTTP)",
                       runs_key: "unixoide" );

register_product(cpe: os_cpe, location: location, port: port, service: "www");
register_product(cpe: hw_cpe, location: location, port: port, service: "www");

report = build_detection_report(app: os_name, version: version, install: location, cpe: os_cpe,
                                concluded: vers[0], concludedUrl: concUrl);

report += '\n\n';

report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe,
                                 concluded: mod[0], concludedUrl: concUrl);

log_message(port: port, data: report);

exit(0);
