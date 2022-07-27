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

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144905");
  script_version("2020-11-10T05:48:31+0000");
  script_tag(name:"last_modification", value:"2020-11-10 11:23:32 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-09 05:31:27 +0000 (Mon, 09 Nov 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Trend Micro Interscan Messaging Security Virtual Appliance Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Trend Micro Interscan Messaging Security Virtual Appliance
  (IMSVA) detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_trend_micro_interscan_messaging_security_virtual_appliance_ssh_login_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_trend_micro_interscan_messaging_security_virtual_appliance_http_detect.nasl");
  script_mandatory_keys("trend_micro/imsva/detected");

  script_xref(name:"URL", value:"https://www.trendmicro.com/en_us/business/products/user-protection/sps/email-and-collaboration/interscan-messaging.html");

  exit(0);
}

if (!get_kb_item("trend_micro/imsva/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
detected_build = "unknown";
location = "/";

foreach source (make_list("ssh-login", "http")) {
  version_list = get_kb_list("trend_micro/imsva/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  build_list = get_kb_list("trend_micro/imsva/" + source + "/*/build");
  foreach build (build_list) {
    if (build != "unknown" && detected_build == "unknown") {
      detected_build = build;
      set_kb_item(name: "trend_micro/imsva/build", value: detected_build);
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:trendmicro:interscan_messaging_security_virtual_appliance:");
if (!cpe)
  cpe = "cpe:/a:trendmicro:interscan_messaging_security_virtual_appliance";

if (ssh_login_ports = get_kb_list("trend_micro/imsva/ssh-login/port")) {
  extra += 'Local Detection over SSH:\n';

  foreach port (ssh_login_ports) {
    concluded = get_kb_item("trend_micro/imsva/ssh-login/" + port + "/concluded");
    extra += '  Port:                           ' + port + '/tcp\n';
    if (concluded)
      extra += '  Concluded from version/product\n';
      extra += '  identification result:          ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "ssh-login");
  }
}

if (http_ports = get_kb_list("trend_micro/imsva/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concluded = get_kb_item("trend_micro/imsva/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    concUrl = get_kb_item("trend_micro/imsva/http/" + port + "/concludedUrl");
    if (concUrl)
      extra += '  Concluded from version/product identification location: ' + concUrl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

register_and_report_os(os: "CentOS", cpe: "cpe:/o:centos:centos",
                       desc: "Trend Micro Interscan Messaging Security Virtual Appliance Detection Consolidation",
                       runs_key:"unixoide");

report = build_detection_report(app: "Trend Micro Interscan Messaging Security Virtual Appliance",
                                version: detected_version, install: location, cpe: cpe,
                                extra: "Build: " + detected_build);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
