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
  script_oid("1.3.6.1.4.1.25623.1.0.144208");
  script_version("2020-07-02T09:25:29+0000");
  script_tag(name:"last_modification", value:"2020-07-07 10:15:52 +0000 (Tue, 07 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-02 07:28:21 +0000 (Thu, 02 Jul 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Fortinet FortiMail Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Fortinet FortiMail detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_fortimail_ssh_login_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_fortimail_http_detect.nasl");
  script_mandatory_keys("fortinet/fortimail/detected");

  script_xref(name:"URL", value:"https://www.fortinet.com/products/email-security");

  exit(0);
}

if (!get_kb_item("fortinet/fortimail/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("ssh-login", "http")) {
  version_list = get_kb_list("fortinet/fortimail/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:fortinet:fortimail:");
if (!cpe)
  cpe = "cpe:/a:fortinet:fortimail";

if (ssh_login_ports = get_kb_list("fortinet/fortimail/ssh-login/port")) {
  extra += 'Local Detection over SSH:\n';

  foreach port (ssh_login_ports) {
    concluded = get_kb_item("fortinet/fortimail/ssh-login/" + port + "/concluded");
    extra += '  Port:                           ' + port + '/tcp\n';
    if (concluded)
      extra += '  Concluded from version/product\n';
      extra += '  identification result:          ' + concluded;

    register_product(cpe: cpe, location: location, port: port, service: "ssh-login");
  }
}

if (http_ports = get_kb_list("fortinet/fortimail/http/port")) {
  if (extra)
    extra += '\n\n';

  extra += 'Remote Detection over HTTP(s):\n';

  foreach port (http_ports) {
    extra += '  Port:   ' + port + '/tcp\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

report = build_detection_report(app: "Fortinet FortiMail", version: detected_version, cpe: cpe, install: "/");

if (extra) {
  report += '\n\nDetection methods:\n';
  report += extra;
}

log_message(port: 0, data: report);

exit(0);
