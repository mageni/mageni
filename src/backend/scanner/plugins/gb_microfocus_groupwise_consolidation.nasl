# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.149204");
  script_version("2023-01-31T10:08:41+0000");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-26 05:10:24 +0000 (Thu, 26 Jan 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Micro Focus / Novell GroupWise Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_microfocus_groupwise_admin_console_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_microfocus_groupwise_http_detect.nasl",
                        "gsf/gb_microfocus_groupwise_pop3_detect.nasl",
                        "gsf/gb_microfocus_groupwise_smtp_detect.nasl",
                        "gsf/gb_microfocus_groupwise_imap_detect.nasl");
  script_mandatory_keys("microfocus/groupwise/detected");

  script_tag(name:"summary", value:"Consolidation of Micro Focus / Novell GroupWise detections.");

  script_xref(name:"URL", value:"https://www.microfocus.com/en-us/products/groupwise/overview");

  exit(0);
}

if (!get_kb_item("microfocus/groupwise/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("smtp", "http", "pop3", "imap", "admin_console")) {
  version_list = get_kb_list("microfocus/groupwise/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:microfocus:groupwise:");
if (!cpe)
  cpe = "cpe:/a:microfocus:groupwise";

if (http_ports = get_kb_list("microfocus/groupwise/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("microfocus/groupwise/http/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    concludedUrl = get_kb_item("microfocus/groupwise/http/" + port + "/concludedUrl");
    if (concludedUrl)
      extra += "  Concluded from version/product identification location: " + concludedUrl + '\n';

    install = get_kb_item("microfocus/groupwise/http/" + port + "/install");

    register_product(cpe: cpe, location: install, port: port, service: "www");
  }
}

if (admin_ports = get_kb_list("microfocus/groupwise/admin_console/port")) {
  foreach port (admin_ports) {
    extra += "Administration Console (HTTP(s)) on port " + port + '/tcp\n';

    concludedUrl = get_kb_item("microfocus/groupwise/admin_console/" + port + "/concludedUrl");
    if (concludedUrl)
      extra += "  Concluded from version/product identification location: " + concludedUrl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "admin_console");
  }
}

if (smtp_ports = get_kb_list("microfocus/groupwise/smtp/port")) {
  foreach port (smtp_ports) {
    extra += "SMTP on port " + port + '/tcp\n';

    concluded = get_kb_item("microfocus/groupwise/smtp/" + port + "/concluded");
    if (concluded)
      extra += "  SMTP Banner: " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "smtp");
  }
}

if (pop3_ports = get_kb_list("microfocus/groupwise/pop3/port")) {
  foreach port (pop3_ports) {
    extra += "POP3 on port " + port + '/tcp\n';

    concluded = get_kb_item("microfocus/groupwise/pop3/" + port + "/concluded");
    if (concluded)
      extra += "  POP3 Banner: " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "pop3");
  }
}

if (imap_ports = get_kb_list("microfocus/groupwise/imap/port")) {
  foreach port (imap_ports) {
    extra += "IMAP on port " + port + '/tcp\n';

    concluded = get_kb_item("microfocus/groupwise/imap/" + port + "/concluded");
    if (concluded)
      extra += "  IMAP Banner: " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "imap");
  }
}

report = build_detection_report(app: "Micro Focus / Novell GroupWise", version: detected_version,
                                install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
