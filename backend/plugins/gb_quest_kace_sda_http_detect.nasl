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
  script_oid("1.3.6.1.4.1.25623.1.0.148118");
  script_version("2022-05-17T11:41:48+0000");
  script_tag(name:"last_modification", value:"2022-05-18 09:49:57 +0000 (Wed, 18 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-13 09:36:20 +0000 (Fri, 13 May 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Quest / Dell KACE Systems Deployment Appliance (SDA) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("KACE-Appliance/banner");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"HTTP based detection of Quest / Dell KACE Systems Deployment
  Appliance (SDA).");

  script_xref(name:"URL", value:"https://www.quest.com/products/kace-systems-deployment-appliance/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/login";

res = http_get_cache(port: port, item: url);

if (("<title>KACE Systems Deployment Appliance</title>" >< res || "kace.js" >< res) &&
    "X-KACE-Appliance" >< res) {
  model = "unknown";
  version = "unknown";

  hw_name = "Quest / Dell KACE Systems Deployment Appliance (SMA)";
  os_name = hw_name + " Firmware";

  # X-KACE-Appliance: k2000
  mod = eregmatch(pattern: "X-(Dell)?KACE-Appliance\s*:\s*(K[0-9]+)", string: res, icase: TRUE);
  if (!isnull(mod[2])) {
    model = toupper(mod[2]);
    hw_name += " " + model;
  }

  # /common/css/print.css?build=8.2.158
  vers = eregmatch(pattern: "\.(js|css)\?build=([0-9.]+)", string: res);
  if (isnull(vers[2]))
    # X-DellKACE-Version: 6.4.120756
    # X-KACE-Version: 8.2.158
    vers = eregmatch(pattern: "X-(Dell)?KACE-Version\s*:\s*([0-9.]+)", string: res, icase: TRUE);

  if (!isnull(vers[2]))
    version = vers[2];

  concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "quest/kace/sda/detected", value: TRUE);
  set_kb_item(name: "quest/kace/sda/http/detected", value: TRUE);

  os_cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:quest:kace_systems_deployment_appliance_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:quest:kace_systems_deployment_appliance_firmware";

  if (model != "unknown")
    hw_cpe = "cpe:/h:quest:kace_" + tolower(model) + "_systems_deployment_appliance";
  else
    hw_cpe = "cpe:/h:quest:kace_systems_deployment_appliance";

  os_register_and_report(os: os_name, cpe: os_cpe, runs_key: "unixoide",
                         desc: "Quest / Dell KACE Systems Deployment Appliance (SDA) Detection (HTTP)");

  register_product(cpe: os_cpe, location: "/", port: port, service: "www");
  register_product(cpe: hw_cpe, location: "/", port: port, service: "www");

  report  = build_detection_report(app: os_name, version: version, install: "/", cpe: os_cpe,
                                   concluded: vers[0], concludedUrl: concUrl);
  report += '\n\n';
  report += build_detection_report(app: hw_name, skip_version: TRUE, install: "/", cpe: hw_cpe,
                                   concluded: mod[0]);

  log_message(port: port, data: report);

  exit(0);
}

exit(0);
