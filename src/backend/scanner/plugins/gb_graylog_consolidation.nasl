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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148575");
  script_version("2022-08-10T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-08-10 10:11:40 +0000 (Wed, 10 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-09 07:42:59 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Graylog Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Graylog detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_graylog_http_detect.nasl",
                      "gb_graylog_rest_api_detect.nasl");
  script_mandatory_keys("graylog/detected");

  script_xref(name:"URL", value:"https://www.graylog.org/");

  exit(0);
}

if (!get_kb_item("graylog/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("http", "rest_api")) {
  version_list = get_kb_list("graylog/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:graylog:graylog:");
if (!cpe)
  cpe = "cpe:/a:graylog:graylog";

os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", desc: "Graylog Detection Consolidation",
                       runs_key: "unixoide");

if (http_ports = get_kb_list("graylog/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    if (id = get_kb_item("graylog/http/" + port + "/extra"))
      extra += '  Additional Information: ' + id + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (rest_ports = get_kb_list("graylog/rest_api/port")) {
  foreach port (rest_ports) {
    extra += 'REST API on port ' + port + '/tcp\n';

    concl = get_kb_item("graylog/rest_api/" + port + "/concluded");
    conclUrl = get_kb_item("graylog/rest_api/" + port + "/concludedUrl");
    if (concl)
      extra += '  Concluded from version/product identification result: ' + concl + '\n';

    if (conclUrl)
      extra += '  Concluded from version/product identification location: ' + conclUrl + '\n';

    if (id = get_kb_item("graylog/rest_api/" + port + "/extra"))
      extra += '  Additional Information: ' + id + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "rest_api");
  }
}

report = build_detection_report(app: "Graylog", version: detected_version, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
