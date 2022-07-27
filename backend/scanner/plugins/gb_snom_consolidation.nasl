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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142000");
  script_version("$Revision: 13720 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-18 08:43:24 +0100 (Mon, 18 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-15 09:14:08 +0700 (Fri, 15 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Snom Detection Consolidation");

  script_tag(name:"summary", value:"The script reports a detected Snom device including the version number.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snom_detect.nasl", "gb_snom_http_detect.nasl");
  script_mandatory_keys("snom/detected");

  script_xref(name:"URL", value:"https://www.snom.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

if (!get_kb_item("snom/detected"))
  exit(0);

detected_version = "unknown";
detected_model = "";

foreach source (make_list("sip", "http")) {
  version_list = get_kb_list("snom/" + source + "/*/version");
  foreach vers (version_list) {
    if (vers != "unknown" && detected_version == "unknown")
      detected_version = vers;
  }

  model_list = get_kb_list("snom/" + source + "/*/model");
  foreach mod (model_list) {
    if (mod != "unknown" && detected_model == "")
      detected_model = mod;
  }
}

if (detected_model != "") {
  cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/h:snom:snom_" + detected_model + ":");
  if (!cpe)
    cpe = "cpe:/h:snom:snom_" + detected_model;
} else {
  cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/h:snom:snom_unknown_model:");
  if (!cpe)
    cpe = "cpe:/h:snom:snom_unknown_model";
}

if (http_ports = get_kb_list("snom/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';
    register_product(cpe: cpe, location: '/', port: port, service: "www");
  }
}

if (sip_ports = get_kb_list("snom/sip/port")) {
  foreach port (sip_ports) {
    proto = get_kb_item("snom/sip/" + port + "/proto");
    concl = get_kb_item("snom/sip/" + port + "/" + proto + "/concluded");
    extra += 'SIP on port ' + port + '/' + proto + '\nBanner: ' + concl + '\n';
    register_product(cpe: cpe, location: port + '/' + proto, port: port, service: "sip");
  }
}

report = build_detection_report(app: "Snom " + detected_model, version: detected_version, install: "/", cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
