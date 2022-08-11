# Copyright (C) 2020 Greenbone Networks GmbH
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

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143631");
  script_version("2020-03-25T06:16:54+0000");
  script_tag(name:"last_modification", value:"2020-03-25 11:04:45 +0000 (Wed, 25 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-24 08:39:18 +0000 (Tue, 24 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Grandstream UCM Detection Consolidation");

  script_tag(name:"summary", value:"Reports the Grandstream UCM model and version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_grandstream_ucm_sip_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_grandstream_ucm_http_detect.nasl");
  script_mandatory_keys("grandstream/ucm/detected");

  script_xref(name:"URL", value:"http://www.grandstream.com/products/ip-pbxs/ucm-series-ip-pbxs");

  exit(0);
}

if (!get_kb_item("grandstream/ucm/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_model = "unknown";
detected_version = "unknown";
location = "/";

foreach source (make_list("http", "sip")) {
  model_list = get_kb_list("grandstream/ucm/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      break;
    }
  }

  version_list = get_kb_list("grandstream/ucm/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

os_name = "Grandstream ";
hw_name = os_name;

if (detected_model != "unknown") {
  os_name += detected_model + " Firmware";
  hw_name += detected_model;

  os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)",
                     base: "cpe:/o:grandstream:" + tolower(model) + "_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:grandstream:" + tolower(model) + "_firmware";

  hw_cpe = "cpe:/h:grandstream:" + tolower(model);
} else {
  os_name += "UCM Unknown Model Firmware";
  hw_name += "UCM Unknown Model";

  os_cpe = build_cpe(value: detected_version, exp:"^([0-9.]+)", base: "cpe:/o:grandstream:ucm_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:grandstream:ucm_firmware";

  hw_cpe = "cpe:/h:grandstream:ucm";
}

register_and_report_os(os: os_name, cpe: os_cpe, desc: "Grandstream UCM Detection Consolidation", runs_key: "unixoide");

if (sip_ports = get_kb_list("grandstream/ucm/sip/port")) {
  foreach port (sip_ports) {
    proto = get_kb_item("grandstream/ucm/sip/" + port + "/proto");
    extra += 'SIP on port ' + port + '/' + proto + '\n';
    concluded = get_kb_item("grandstream/ucm/sip/" + port + "/concluded");
    if (concluded)
      extra += '  SIP Banner: ' + concluded + '\n';

    register_product(cpe: hw_cpe, location: location, port: port, service: "sip", proto: proto);
    register_product(cpe: os_cpe, location: location, port: port, service: "sip", proto: proto);
  }
}

if (http_ports = get_kb_list("grandstream/ucm/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';
    concluded = get_kb_item("grandstream/ucm/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

report  = build_detection_report(app: os_name, version: detected_version, install: location, cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
