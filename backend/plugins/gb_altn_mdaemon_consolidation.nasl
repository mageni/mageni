# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.145329");
  script_version("2021-02-08T15:30:09+0000");
  script_tag(name:"last_modification", value:"2021-02-09 11:23:12 +0000 (Tue, 09 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-08 04:38:39 +0000 (Mon, 08 Feb 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Alt-N MDaemon Mail Server Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Alt-N MDaemon Mail Server detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_altn_mdaemon_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_altn_mdaemon_pop3_detect.nasl", "gsf/gb_altn_mdaemon_imap_detect.nasl",
                        "gsf/gb_altn_mdaemon_smtp_detect.nasl");
  script_mandatory_keys("altn/mdaemon/detected");

  script_xref(name:"URL", value:"https://www.altn.com/Products/MDaemon-Email-Server-Windows/");

  exit(0);
}

if (!get_kb_item("altn/mdaemon/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("http", "pop3", "imap", "smtp")) {
  version_list = get_kb_list("altn/mdaemon/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:alt-n:mdaemon:");
if (!cpe)
  cpe = "cpe:/a:alt-n:mdaemon";

register_and_report_os(os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows",
                       desc: "Alt-N MDaemon Mail Server Detection Consolidation", runs_key: "windows");

if (http_ports = get_kb_list("altn/mdaemon/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concluded = get_kb_item("altn/mdaemon/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (pop3_ports = get_kb_list("altn/mdaemon/pop3/port")) {
  foreach port (pop3_ports) {
    extra += 'POP3 on port ' + port + '/tcp\n';

    concluded = get_kb_item("altn/mdaemon/pop3/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "pop3");
  }
}

if (imap_ports = get_kb_list("altn/mdaemon/imap/port")) {
  foreach port (imap_ports) {
    extra += 'IMAP on port ' + port + '/tcp\n';

    concluded = get_kb_item("altn/mdaemon/imap/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "imap");
  }
}

if (smtp_ports = get_kb_list("altn/mdaemon/smtp/port")) {
  foreach port (smtp_ports) {
    extra += 'SMTP on port ' + port + '/tcp\n';

    concluded = get_kb_item("altn/mdaemon/smtp/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "smtp");
  }
}

report = build_detection_report(app: "Alt-N MDaemon Mail Server", version: detected_version, install: location,
                                cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
