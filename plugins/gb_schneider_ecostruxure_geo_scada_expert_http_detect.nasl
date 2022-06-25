# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.141106");
  script_version("2022-02-21T05:29:58+0000");
  script_tag(name:"last_modification", value:"2022-02-21 05:29:58 +0000 (Mon, 21 Feb 2022)");
  script_tag(name:"creation_date", value:"2018-05-17 15:22:07 +0700 (Thu, 17 May 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Schneider Electric EcoStruxure Geo SCADA Expert Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Schneider Electric EcoStruxure Geo SCADA
  Expert (formerly ClearSCADA).");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.se.com/us/en/product-range/61264-ecostruxure-geo-scada-expert/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

res = http_get_cache(port: port, item: "/");

if (('title="ClearSCADA Home"' >< res || 'title="Geo SCADA Expert Home"' >< res) && "CurUser" >< res) {
  version = "unknown";

  # Server: ClearSCADA/6.74.5192.1
  vers = eregmatch(pattern: "Server: ClearSCADA/([0-9.]+)", string: res);
  if (!isnull(vers[1]))
    version = vers[1];
  else {
    url = "/alarms/";
    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req);

    # /file/ViewXCtrl-77.cab#Version=6,77,5882,0"
    vers = eregmatch(pattern: "cab#Version=([0-9,]+)", string: res);
    if (!isnull(vers[1])) {
      version = str_replace(string: vers[1], find: ",", replace: ".");
      concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
    }
  }

  set_kb_item(name: "schneider/geoscada/detected", value: TRUE);
  set_kb_item(name: "schneider/geoscada/http/detected", value: TRUE);

  os_register_and_report(os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows",
                         desc: "Schneider Electric ClearSCADA Detection", runs_key: "windows");

  cpe1 = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:schneider-electric:ecostruxure_geo_scada_expert:");
  cpe2 = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:schneider-electric:clearscada:");
  if (!cpe1) {
    cpe1 = "cpe:/a:schneider-electric:ecostruxure_geo_scada_expert";
    cpe2 = "cpe:/a:schneider-electric:clearscada";
  }

  register_product(cpe: cpe1, location: "/", port: port, service: "www");
  register_product(cpe: cpe2, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Schneider Electric EcoStruxure Geo SCADA Expert",
                                           version: version, install: "/", cpe: cpe1, concluded: vers[0],
                                           concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
