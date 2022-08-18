# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148606");
  script_version("2022-08-17T09:34:43+0000");
  script_tag(name:"last_modification", value:"2022-08-17 09:34:43 +0000 (Wed, 17 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-17 03:49:33 +0000 (Wed, 17 Aug 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Zimbra Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_zimbra_admin_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_zimbra_imap_detect.nasl");
  script_mandatory_keys("zimbra/detected");

  script_tag(name:"summary", value:"Consolidation of Zimbra detections.");

  script_xref(name:"URL", value:"https://www.zimbra.com/");

  exit(0);
}

if (!get_kb_item("zimbra/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("imap", "http", "http-admin", "pop3")) {
  version_list = get_kb_list("zimbra/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe1 = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:zimbra:collaboration:");
cpe2 = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:synacor:zimbra_collaboration_suite:");
if (!cpe1) {
  cpe1 = "cpe:/a:zimbra:collaboration";
  cpe2 = "cpe:/a:synacor:zimbra_collaboration_suite";
}

os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", desc: "Zimbra Detection Consolidation",
                       runs_key: "unixoide");

if (http_ports = get_kb_list("zimbra/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port: ' + port + '/tcp\n';

    concluded = get_kb_item("zimbra/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    conclUrl = get_kb_item("zimbra/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += '  Concluded from version/product identification location: ' + conclUrl + '\n';

    register_product(cpe: cpe1, location: location, port: port, service: "www");
    register_product(cpe: cpe2, location: location, port: port, service: "www");
  }
}

if (admin_ports = get_kb_list("zimbra/http-admin/port")) {
  foreach port (admin_ports) {
    extra += 'Admin Console over HTTP(s) on port: ' + port + '/tcp\n';

    concluded = get_kb_item("zimbra/http-admin/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    conclUrl = get_kb_item("zimbra/http-admin/" + port + "/concludedUrl");
    if (conclUrl)
      extra += '  Concluded from version/product identification location: ' + conclUrl + '\n';

    loc = get_kb_item("zimbra/http-admin/" + port + "/location");
    if (!loc)
      loc = "/";

    register_product(cpe: cpe1, location: loc, port: port, service: "www-admin");
    register_product(cpe: cpe2, location: loc, port: port, service: "www-admin");
    # nb: Register this as well as a www service for active checks
    register_product(cpe: cpe2, location: loc, port: port, service: "www");
  }
}

if (pop3_ports = get_kb_list("zimbra/pop3/port")) {
  foreach port (pop3_ports) {
    extra += 'POP3 on port ' + port + '/tcp\n';

    concluded = get_kb_item("zimbra/pop3/" + port + "/concluded");
    if (concluded)
      extra += '  POP3 Banner: ' + concluded + '\n';

    register_product(cpe: cpe1, location: location, port: port, service: "pop3");
    register_product(cpe: cpe2, location: location, port: port, service: "pop3");
  }
}

if (imap_ports = get_kb_list("zimbra/imap/port")) {
  foreach port (imap_ports) {
    extra += 'IMAP on port ' + port + '/tcp\n';

    concluded = get_kb_item("zimbra/imap/" + port + "/concluded");
    if (concluded)
      extra += '  IMAP Banner: ' + concluded + '\n';

    register_product(cpe: cpe1, location: location, port: port, service: "imap");
    register_product(cpe: cpe2, location: location, port: port, service: "imap");
  }
}

report = build_detection_report(app: "Zimbra", version: detected_version, install: location, cpe: cpe1);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
