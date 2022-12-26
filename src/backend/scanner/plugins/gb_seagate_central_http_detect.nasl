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
  script_oid("1.3.6.1.4.1.25623.1.0.149001");
  script_version("2022-12-09T13:56:52+0000");
  script_tag(name:"last_modification", value:"2022-12-09 13:56:52 +0000 (Fri, 09 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-07 05:49:18 +0000 (Wed, 07 Dec 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Seagate Central Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Seagate Central.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.seagate.com/as/en/support/external-hard-drives/network-storage/seagate-central/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

res = http_get_cache(port: port, item: "/index.php");

if ('title="Seagate Central"' >< res && "<title>Seagate Central</title>" >< res) {
  version = "unknown";
  location = "/";

  url = "/index.php/Start/get_firmware";
  headers = make_array("X-Requested-With", "XMLHttpRequest");

  req = http_get_req(port: port, url: url, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  # <firmware><description>Cirrus NAS</description><version>2014.0410.0026-F</version><update_status>no</update_status><release_notes version="2014.0410.0026-F" date="11-04-2014"></release_notes><auto_update time="01:00" never="no" ask="no"></auto_update></firmware>
  vers = eregmatch(pattern: "<version>([^<]+)</version>", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  set_kb_item(name: "seagate/central/detected", value: TRUE);
  set_kb_item(name: "seagate/central/http/detected", value: TRUE);

  os_name = "Seagate Central Firmware";
  hw_name = "Seagate Central Unknown Model";

  os_cpe = build_cpe(value: tolower(version), exp: "^([0-9A-Z.-]+)", base: "cpe:/o:seagate:seagate_central_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:seagate:seagate_central_firmware";

  hw_cpe = "cpe:/h:seagate:seagate_central";

  os_register_and_report(os: "Seagate Central Firmware", cpe: os_cpe, runs_key: "unixoide", port: port,
                         desc: "Seagate Central Detection (HTTP)");

  register_product(cpe: os_cpe, location: location, port: port, service: "www");
  register_product(cpe: hw_cpe, location: location, port: port, service: "www");

  report  = build_detection_report(app: os_name, version: version, install: location, cpe: os_cpe,
                                   concluded: vers[0], concludedUrl: conclUrl);
  report += '\n\n';
  report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

  log_message(port: port, data: report);
}

exit(0);
