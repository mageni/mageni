# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.144537");
  script_version("2020-09-09T06:54:10+0000");
  script_tag(name:"last_modification", value:"2020-09-09 06:54:10 +0000 (Wed, 09 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-09 05:30:36 +0000 (Wed, 09 Sep 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("D-Link DCS Device Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of D-Link DCS devices.");

  script_xref(name:"URL", value:"https://www.dlink.com/en/consumer/cameras");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

banner = http_get_remote_headers(port: port);
if (banner !~ '(Basic|Digest) realm="DCS-')
  exit(0);

version = "unknown";
model = "unknown";

set_kb_item(name: "Host/is_dlink_dcs_device", value: TRUE);
set_kb_item(name: "Host/is_dlink_device", value: TRUE);

# WWW-Authenticate: Basic realm="DCS-2530L"
# WWW-Authenticate: Basic realm="DCS-932L_68"
# WWW-Authenticate: Digest realm="DCS-2530L"
mod = eregmatch(pattern: 'Basic realm="(DCS\\-[^"]+)"', string: banner);
if (!isnull(mod[1]))
  model = mod[1];

if (model != "unknown") {
  os_name = "D-Link " + model + " Firmware";
  hw_name = "D-Link " + model;

  os_cpe = "cpe:/o:d-link:" + tolower(model) + "_firmware";
  hw_cpe = "cpe:/h:d-link:" + tolower(model);
} else {
  os_name = "D-Link DCS Unknown Model Firmware";
  hw_name = "D-Link DCS Unknown Model";

  os_cpe = "cpe:/o:d-link:dcs_firmware";
  hw_cpe = "cpe:/h:d-link:dcs";
}

register_and_report_os(os: os_name, cpe: os_cpe, banner_type: "D-Link DCS Device Login Page", port: port,
                       desc: "D-Link DCS Device Detection (HTTP)", runs_key: "unixoide");

register_product(cpe: os_cpe, location: "/", port: port, service: "www");
register_product(cpe: hw_cpe, location: "/", port: port, service: "www");

report = build_detection_report(app: os_name, version: version, install: "/", cpe: os_cpe);
report += '\n\n' + build_detection_report(app: hw_name, install: "/", cpe: hw_cpe, skip_version: TRUE);

log_message(port: port, data: report);

exit(0);
