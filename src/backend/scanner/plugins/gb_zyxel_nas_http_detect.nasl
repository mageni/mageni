# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.148721");
  script_version("2022-09-15T10:11:07+0000");
  script_tag(name:"last_modification", value:"2022-09-15 10:11:07 +0000 (Thu, 15 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-13 06:47:59 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Zyxel NAS Device Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 5000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Zyxel NAS devices.");

  script_xref(name:"URL", value:"https://www.zyxel.com/products_services/home_connectivity-personal_cloud_storage.shtml?t=c");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 5000);

url = "/";
install = url;

res = http_get_cache(port: port, item: url);

if (res =~ "^HTTP/1\.[01] 30.") {
  url = http_extract_location_from_redirect(port: port, data: res, current_dir: "/");
  if (!isnull(url)) {
    res = http_get_cache(port: port, item: url);

    if (res =~ "^HTTP/1\.[01] 30.") {
      url = http_extract_location_from_redirect(port: port, data: res, current_dir: "/");
      if (!isnull(url)) {
        res = http_get_cache(port: port, item: url);
      }
    }
  }
}

if (('class="loginNote-text"' >< res || "getWhoami" >< res) &&
    "utility/flag.js" >< res && ("login-nasImage" >< res || "desktopMainPage-bg" >< res)) {
  model = "unknown";
  version = "unknown";

  path = eregmatch(pattern: "^(.*/desktop,/)", string: url);
  if (!isnull(path[1])) {
    url = path[1] + "utility/flag.js";
    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

    # 'modelName':'NAS326',
    # 'storage':'2bay',
    # 'company':'ZyXEL',
    # 'product':'NAS',
    mod = eregmatch(pattern: "'modelName'\s*:\s*'(NAS[^']+)'", string: res);
    if (!isnull(mod[1])) {
      model = mod[1];
      concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
    }
  }

  if (model != "unknown") {
    os_app = "Zyxel " + model + " Firmware";
    hw_app = "Zyxel " + model;
    os_cpe = "cpe:/o:zyxel:" + tolower(model) + "_firmware";
    hw_cpe = "cpe:/h:zyxel:" + tolower(model);
  } else {
    os_app = "Zyxel NAS Firmware";
    hw_app = "Zyxel NAS Unknown Model";
    os_cpe = "cpe:/o:zyxel:nas_firmware";
    hw_cpe = "cpe:/h:zyxel:nas";
  }

  os_register_and_report(os: os_app , cpe: os_cpe, banner_type: "Zyxel NAS Device Login Page", port: port,
                         desc: "Zyxel NAS Device Detection (HTTP)", runs_key: "unixoide" );

  register_product(cpe: os_cpe, location: install, port: port, service: "www");
  register_product(cpe: hw_cpe, location: install, port: port, service: "www");

  report = build_detection_report(app: os_app, version: version, install: install, cpe: os_cpe);

  report += '\n\n';

  report += build_detection_report(app: hw_app, skip_version: TRUE, install: install, cpe: hw_cpe,
                                   concluded: mod[0], concludedUrl: concUrl);

  log_message(port: port, data: report);
  exit(0);
}

exit(0);
