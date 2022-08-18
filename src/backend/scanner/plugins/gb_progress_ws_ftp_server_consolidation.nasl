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

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148588");
  script_version("2022-08-15T10:52:44+0000");
  script_tag(name:"last_modification", value:"2022-08-15 10:52:44 +0000 (Mon, 15 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-12 02:32:58 +0000 (Fri, 12 Aug 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Progress WS_FTP Server Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Progress WS_FTP Server detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_progress_ws_ftp_server_ftp_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_progress_ws_ftp_server_http_detect.nasl",
                        "gsf/gb_progress_ws_ftp_server_ssh_detect.nasl");
  script_mandatory_keys("progress/ws_ftp/server/detected");

  script_xref(name:"URL", value:"https://www.progress.com/ws_ftp");

  exit(0);
}

if (!get_kb_item("progress/ws_ftp/server/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

app_name = "Progress WS_FTP Server";
detected_version = "unknown";
location = "/";

foreach source (make_list("ftp", "ssh", "http")) {
  version_list = get_kb_list("progress/ws_ftp/server/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe1 = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:progress:ipswitch_ws_ftp_server:");
cpe2 = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:ipswitch:ws_ftp_server:");
if (!cpe1) {
  cpe1 = "cpe:/a:progress:ipswitch_ws_ftp_server";
  cpe2 = "cpe:/a:ipswitch:ws_ftp_server";
}

os_register_and_report(os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", runs_key: "windows",
                       desc: "Progress WS_FTP Server Detection Consolidation");

if (http_ports = get_kb_list("progress/ws_ftp/server/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port: ' + port + '/tcp\n';

    conclUrl = get_kb_item("progress/ws_ftp/server/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += '  Concluded from version/product identification location:' + conclUrl + '\n';

    register_product(cpe: cpe1, location: location, port: port, service: "www");
    register_product(cpe: cpe2, location: location, port: port, service: "www");
  }
}

if (ssh_ports = get_kb_list("progress/ws_ftp/server/ssh/port")) {
  foreach port (ssh_ports) {
    extra += 'SSH on port: ' + port + '/tcp\n';

    concluded = get_kb_item("progress/ws_ftp/server/ssh/" + port + "/concluded");
    if (concluded)
      extra += '  SSH Banner: ' + concluded + '\n';

    register_product(cpe: cpe1, location: location, port: port, service: "ssh");
    register_product(cpe: cpe2, location: location, port: port, service: "ssh");
  }
}

if (ftp_ports = get_kb_list("progress/ws_ftp/server/ftp/port")) {
  foreach port (ftp_ports) {
    extra += 'FTP on port: ' + port + '/tcp\n';

    concluded = get_kb_item("progress/ws_ftp/server/ftp/" + port + "/concluded");
    if (concluded)
      extra += '  FTP Banner: ' + concluded + '\n';

    register_product(cpe: cpe1, location: location, port: port, service: "ftp");
    register_product(cpe: cpe2, location: location, port: port, service: "ftp");
  }
}

report  = build_detection_report(app: app_name, version: detected_version, install: location, cpe: cpe1);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
