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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144098");
  script_version("2020-06-09T09:51:17+0000");
  script_tag(name:"last_modification", value:"2020-06-10 10:58:50 +0000 (Wed, 10 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-09 09:18:01 +0000 (Tue, 09 Jun 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ejabberd Consolidation");

  script_tag(name:"summary", value:"Reports the ejabberd version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_ejabberd_xmpp_detect.nasl", "gb_ejabberd_http_detect.nasl", "gb_ejabberd_sip_detect.nasl");
  script_mandatory_keys("ejabberd/detected");

  exit(0);
}

if (!get_kb_item("ejabberd/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("sip", "http", "xmpp")) {
  version_list = get_kb_list("ejabberd/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

if (detected_version != "unknown")
  cpe = build_cpe(value: detected_version, exp: "^([0-9a-z+~.-]+)", base: "cpe:/a:process-one:ejabberd:");

if (!cpe)
  cpe = "cpe:/a:process-one:ejabberd";

if (http_ports = get_kb_list("ejabberd/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';
    concluded = get_kb_item("ejabberd/http/" + port + "/concluded");
    concUrl = get_kb_item("ejabberd/http/" + port + "/concludedUrl");
    if (concluded) {
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';
      extra += '  Concluded from version/product identification location: ' + concUrl + '\n';
    }

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (xmpp_ports = get_kb_list("ejabberd/xmpp/port")) {
  foreach port (xmpp_ports) {
    extra += 'XMPP on port ' + port + '/tcp\n';
    concluded = get_kb_item("ejabberd/xmpp/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: cpe, location: "/", port: port, service: "xmpp");
  }
}

if (sip_ports = get_kb_list("ejabberd/sip/port")) {
  foreach port (sip_ports) {
    proto = get_kb_item("ejabberd/sip/" + port + "/proto");
    extra += 'SIP on port ' + port + '/' + proto + '\n';
    concluded = get_kb_item("ejabberd/sip/" + port + "/concluded");
    extra += '  SIP banner: ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "sip", proto: proto);
  }
}

report = build_detection_report(app: "ejabberd", version: detected_version, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
