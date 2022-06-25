# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.142677");
  script_version("2019-07-31T06:35:42+0000");
  script_tag(name:"last_modification", value:"2019-07-31 06:35:42 +0000 (Wed, 31 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-30 09:14:47 +0000 (Tue, 30 Jul 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("AVM FRITZ!WLAN Repeater Consolidation");

  script_tag(name:"summary", value:"The script reports a detected AVM FRITZ!WLAN Repeater including the version
  number.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_avm_fritz_wlanrepeater_detect_http.nasl", "gb_avm_fritz_wlanrepeater_detect_upnp.nasl");
  script_mandatory_keys("avm_fritz_wlanrepeater/detected");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

if (!get_kb_item("avm_fritz_wlanrepeater/detected"))
  exit(0);

detected_model = "unknown";
detected_fw    = "unknown";

foreach source (make_list("upnp", "http")) {
  model_list = get_kb_list("avm_fritz_wlanrepeater/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "avm_fritz_wlanrepeater/model", value: detected_model);
    }
  }

  fw_list = get_kb_list("avm_fritz_wlanrepeater/" + source + "/*/fw_version");
  foreach fw (fw_list) {
    if (fw != "unknown" && detected_fw == "unknown") {
      detected_fw = fw;
      set_kb_item(name: "avm_fritz_wlanrepeater/firmware_version", value: detected_fw);
    }
  }
}

if (detected_model != "unknown") {

  app_name = "AVM FRITZ!WLAN Repeater " + detected_model;

  os_cpe = build_cpe(value: detected_fw, exp: "^([0-9.]+)",
                     base: "cpe:/o:avm:fritz%21wlan_repeater_" + tolower(detected_model) + ":");
  app_cpe = build_cpe(value: detected_fw, exp: "^([0-9.]+)",
                      base: "cpe:/a:avm:fritz%21wlan_repeater_" + tolower(detected_model) + ":");
  if (!os_cpe) {
    os_cpe = "cpe:/o:avm:fritz%21wlan_repeater_" + tolower(detected_model);
    app_cpe = "cpe:/a:avm:fritz%21wlan_repeater_" + tolower(detected_model);
  }

  hw_cpe = "cpe:/h:avm:fritz%21wlan_repeater_" + tolower(detected_model);
} else {

  app_name = "AVM FRITZ!WLAN Repeater Unknown Model";

  os_cpe = build_cpe(value: detected_fw, exp: "^([0-9.]+)", base: "cpe:/o:avm:fritz%21wlan_repeater:");
  app_cpe = build_cpe(value: detected_fw, exp: "^([0-9.]+)", base: "cpe:/a:avm:fritz%21wlan_repeater:");
  if (!os_cpe) {
    os_cpe = "cpe:/o:avm:fritz%21wlan_repeater";
    app_cpe = "cpe:/a:avm:fritz%21wlan_repeater";
  }

  hw_cpe = "cpe:/h:avm:fritz%21wlan_repeater";
}

register_and_report_os(os: "AVM FRITZ!WLAN Repeater", cpe: os_cpe, desc: "AVM FRITZ!WLAN Repeater Consolidation",
                       runs_key: "unixoide");

location = "/";

if (http_ports = get_kb_list("avm_fritz_wlanrepeater/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';
    concluded = get_kb_item("avm_fritz_wlanrepeater/http/" + port + "/concluded");
    if (concluded)
      extra += '  HTML/Logo: ' + concluded + '\n';

    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: app_cpe, location: location, port: port, service: "www");
  }
}

if (upnp_ports = get_kb_list("avm_fritz_wlanrepeater/upnp/port")) {
  foreach port (upnp_ports) {
    concluded = get_kb_item("avm_fritz_wlanrepeater/upnp/" + port + "/concluded");
    extra += 'UPnP on port ' + port + '/udp\n';
    extra += '  Banner: ' + concluded + '\n';
    register_product(cpe: hw_cpe, location: location, port: port, service: "upnp", proto: "udp");
    register_product(cpe: os_cpe, location: location, port: port, service: "upnp", proto: "udp");
    register_product(cpe: app_cpe, location: location, port: port, service: "upnp", proto: "udp");
  }
}

report = build_detection_report(app: app_name, version: detected_fw,
                                install: location, cpe: os_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
