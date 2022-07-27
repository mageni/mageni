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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144579");
  script_version("2020-09-17T10:06:32+0000");
  script_tag(name:"last_modification", value:"2020-09-23 10:13:12 +0000 (Wed, 23 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-16 04:17:59 +0000 (Wed, 16 Sep 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HCL / IBM / Lotus Domino Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_hcl_domino_imap_detect.nasl", "gb_hcl_domino_pop3_detect.nasl",
                      "gb_hcl_domino_smtp_detect.nasl");
  script_mandatory_keys("hcl/domino/detected");

  script_tag(name:"summary", value:"Consolidation of HCL Domino (formerly IBM/Lotus Domino) detections.");

  script_xref(name:"URL", value:"https://www.hcltechsw.com/products/domino");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

if (!get_kb_item("hcl/domino/detected"))
  exit(0);

detected_version = "unknown";
location = "/";

foreach source (make_list("imap", "pop3", "smtp", "http")) {
  version_list = get_kb_list("hcl/domino/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

# nb. The HCL CPE is not by NIST assigned yet
cpe1 = build_cpe(value: tolower(detected_version), exp: "^([0-9a-x.]+)", base: "cpe:/a:hcltech:domino:");
cpe2 = build_cpe(value: tolower(detected_version), exp: "^([0-9a-x.]+)", base: "cpe:/a:ibm:lotus_domino:");
if (!cpe1) {
  cpe1 = "cpe:/a:hcltech:domino";
  cpe2 = "cpe:/a:ibm:lotus_domino";
}

if (smtp_ports = get_kb_list("hcl/domino/smtp/port")) {
  foreach port (smtp_ports) {
    extra += 'SMTP on port ' + port + '/tcp\n';

    concluded = get_kb_item("hcl/domino/smtp/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from banner: ' + concluded + '\n';

    register_product(cpe: cpe1, location: location, port: port, service: "smtp");
    register_product(cpe: cpe2, location: location, port: port, service: "smtp");
  }
}

if (imap_ports = get_kb_list("hcl/domino/imap/port")) {
  foreach port (imap_ports) {
    extra += 'IMAP on port ' + port + '/tcp\n';

    concluded = get_kb_item("hcl/domino/imap/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from banner: ' + concluded + '\n';

    register_product(cpe: cpe1, location: location, port: port, service: "imap");
    register_product(cpe: cpe2, location: location, port: port, service: "imap");
  }
}

if (pop3_ports = get_kb_list("hcl/domino/pop3/port")) {
  foreach port (pop3_ports) {
    extra += 'POP3 on port ' + port + '/tcp\n';

    concluded = get_kb_item("hcl/domino/pop3/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from banner: ' + concluded + '\n';

    register_product(cpe: cpe1, location: location, port: port, service: "pop3");
    register_product(cpe: cpe2, location: location, port: port, service: "pop3");
  }
}

if (http_ports = get_kb_list("hcl/domino/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concluded = get_kb_item("hcl/domino/http/" + port + "/concluded");
    if (concluded)
      extra += '  The following URLs where used for the product / version detection (URL : exposed version):' +
               concluded;
  }
}

report = build_detection_report(app: "HCL Domino", version: detected_version, install: location,
                                cpe: cpe1);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
