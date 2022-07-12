# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900839");
  script_version("2022-05-24T09:30:09+0000");
  script_tag(name:"last_modification", value:"2022-05-24 09:30:09 +0000 (Tue, 24 May 2022)");
  script_tag(name:"creation_date", value:"2009-09-15 09:32:43 +0200 (Tue, 15 Sep 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SurgeMail Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_surgemail_http_detect.nasl", "gb_surgemail_imap_detect.nasl",
                      "gb_surgemail_pop3_detect.nasl", "gb_surgemail_smtp_detect.nasl");
  script_mandatory_keys("surgemail/detected");

  script_tag(name:"summary", value:"Consolidation of SurgeMail detections.");

  script_xref(name:"URL", value:"https://surgemail.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

if (!get_kb_item("surgemail/detected"))
  exit(0);

detected_version = "unknown";
location = "/";

foreach source (make_list("imap", "smtp", "pop3", "http")) {
  version_list = get_kb_list("surgemail/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: tolower(detected_version), exp: "^([0-9a-z.-]+)", base: "cpe:/a:netwin:surgemail:");
if (!cpe)
  cpe = "cpe:/a:netwin:surgemail";

if (smtp_ports = get_kb_list("surgemail/smtp/port")) {
  foreach port (smtp_ports) {
    extra += 'SMTP on port ' + port + '/tcp\n';

    concluded = get_kb_item("surgemail/smtp/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from banner: ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "smtp");
  }
}

if (imap_ports = get_kb_list("surgemail/imap/port")) {
  foreach port (imap_ports) {
    extra += 'IMAP on port ' + port + '/tcp\n';

    concluded = get_kb_item("surgemail/imap/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from banner: ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "imap");
  }
}

if (pop3_ports = get_kb_list("surgemail/pop3/port")) {
  foreach port (pop3_ports) {
    extra += 'POP3 on port ' + port + '/tcp\n';

    concluded = get_kb_item("surgemail/pop3/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from banner: ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "pop3");
  }
}

if (http_ports = get_kb_list("surgemail/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concluded = get_kb_item("surgemail/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    concludedUrl = get_kb_item("surgemail/http/" + port + "/concludedUrl");
    if (concludedUrl)
      extra += '  Concluded from version/product identification location: ' + concludedUrl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

report = build_detection_report(app: "SurgeMail", version: detected_version, install: location,
                                cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
