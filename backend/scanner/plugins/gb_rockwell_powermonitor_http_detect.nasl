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
  script_oid("1.3.6.1.4.1.25623.1.0.142010");
  script_version("$Revision: 13782 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-20 11:28:14 +0100 (Wed, 20 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-20 16:34:48 +0700 (Wed, 20 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Rockwell Automation PowerMonitor Detection (HTTP)");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Rockwell Automation PowerMonitor
devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://ab.rockwellautomation.com/Energy-Monitoring/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/overview.shtm");

if ("Rockwell Automation" >< res && "<title>PowerMonitor" >< res) {
  version = "unknown";

  res2 = http_get_cache(port: port, item: "/");

  mod = eregmatch(pattern: "<title>Powermonitor ([0-9]+)", string: res2, icase: TRUE);
  if (!isnull(mod[1]))
    model = mod[1];

  # "Firmware_Revision">Revision 4.10
  vers = eregmatch(pattern: '"Firmware_Revision">Revision ([0-9.]+)', string: res);
  if (!isnull(vers[1]))
    version = vers[1];
  else {
    # <td>Operating System Version</td>
    # <td><div id = "OS">411</div></td>
    vers = eregmatch(pattern: '"OS">([0-9]+)', string: res);
    if (!isnull(vers[1]))
      version = vers[1];
  }

  # "Ethernet_Address">F4:54:33:54:C0:E1
  mac = eregmatch(pattern: '"Ethernet_Address">([A-F0-9:]{17})', string: res);
  if (!isnull(mac[1])) {
    register_host_detail(name: "MAC", value: mac[1], desc: "gb_rockwell_powermonitor_http_detect.nasl");
    replace_kb_item(name: "Host/mac_address", value: mac[1]);
    extra = 'Mac Address:   ' + mac[1] + '\n';
  }

  set_kb_item(name: "rockwell_powermonitor/detected", value: TRUE);

  if (model) {
    app_cpe = build_cpe(value: version, exp: "^([0-9.]+)",
                        base: "cpe:/a:rockwellautomation:powermonitor" + model + ":");
    os_cpe = build_cpe(value: version, exp: "^([0-9.]+)",
                        base: "cpe:/o:rockwellautomation:powermonitor" + model + ":");
    hw_cpe = "cpe:/h:rockwellautomation:powermeter" + model;
  } else {
    app_cpe = build_cpe(value: version, exp: "^([0-9.]+)",
                        base: "cpe:/a:rockwellautomation:powermonitor:");
    os_cpe = build_cpe(value: version, exp: "^([0-9.]+)",
                        base: "cpe:/o:rockwellautomation:powermonitor:");
    hw_cpe = "cpe:/h:rockwellautomation:powermeter";
  }

  register_and_report_os(os: "Rockwell Automation PowerMonitor Firmware", cpe: os_cpe,
                       desc: "Rockwell Automation PowerMonitor Detection (HTTP)", runs_key: "unixoide");

  register_product(cpe: hw_cpe, location: "/", port: port, service: "www");
  register_product(cpe: os_cpe, location: "/", port: port, service: "www");
  register_product(cpe: app_cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Rockwell Automation PowerMonitor " + model, version: version,
                                           install: "/", cpe: app_cpe, concluded: vers[0], extra: extra),
              port: port);
  exit(0);
}

exit(0);
