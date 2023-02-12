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
  script_oid("1.3.6.1.4.1.25623.1.0.106864");
  script_version("2023-01-10T10:12:01+0000");
  script_tag(name:"last_modification", value:"2023-01-10 10:12:01 +0000 (Tue, 10 Jan 2023)");
  script_tag(name:"creation_date", value:"2017-06-12 15:55:23 +0700 (Mon, 12 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Sophos Cyberoam UTM/NGFW Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://web.archive.org/web/20161012013142/https://www.cyberoam.com/networksecurity.html");

  script_tag(name:"summary", value:"HTTP based detection of Sophos Cyberoam UTM/NGFW.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/corporate/webpages/login.jsp";
res = http_get_cache(port: port, item: url);

if ("<title>Cyberoam</title>" >< res && "OWN_STATUS" >< res && "AUXILIARY" >< res) {
  version = "unknown";
  install = "/";
  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  vers = eregmatch(pattern: "ver=([0-9.]+) build ([0-9])([0-9]+)", string: res);
  if (!isnull(vers[1]) && !isnull(vers[2]) && !isnull(vers[3])) {
    # we get something like 10.06 build 5050 which is actually 10.06.5 build 050
    version = vers[1] + "." + vers[2] + "." + vers[3];
  }

  set_kb_item(name: "sophos/cyberoam_utm_ngfw/detected", value: TRUE);
  set_kb_item(name: "sophos/cyberoam_utm_ngfw/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:cyberoam:cyberoam_os:");
  if (!cpe)
    cpe = "cpe:/o:cyberoam:cyberoam_os";

  register_product(cpe: cpe, location: install, port: port, service: "www");
  os_register_and_report(os: "Cyberoam OS", cpe: cpe, port: port, banner_type: "HTTP login page",
                         desc: "Sophos Cyberoam UTM/NGFW Detection (HTTP)", runs_key: "unixoide");

  log_message(data: build_detection_report(app: "Sophos Cyberoam UTM/NGFW", version: version, install: install,
                                           cpe: cpe, concluded: vers[0], concludedUrl: conclUrl),
              port: port);
}

exit(0);
