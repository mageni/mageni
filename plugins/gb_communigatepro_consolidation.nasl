###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_communigatepro_consolidation.nasl 13140 2019-01-18 08:26:06Z asteins $
#
# CommuniGatePro Detection Consolidation
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140688");
  script_version("$Revision: 13140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-18 09:26:06 +0100 (Fri, 18 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-01-15 15:48:28 +0700 (Mon, 15 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("CommuniGatePro Detection Consolidation");

  script_tag(name:"summary", value:"The script reports a detected CommuniGate Pro including the version number
and exposed services.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_communigatepro_http_detect.nasl", "gb_communigatepro_smtp_detect.nasl",
                      "gb_communigatepro_imap_detect.nasl");
  script_mandatory_keys("communigatepro/detected");

  script_xref(name:"URL", value:"https://www.communigate.com/");

  exit(0);
}

include("host_details.inc");

if( ! get_kb_item( "communigatepro/detected" ) ) exit( 0 );

detected_version = "unknown";

foreach source (make_list("http", "smtp", "imap")) {
  if (detected_version != "unknown")
    break;

  version_list = get_kb_list("communigatepro/" + source + "/*/version");
  foreach version (version_list) {
    if (version && detected_version == "unknown") {
      detected_version = version;
      set_kb_item(name: "communigatepro/version", value: version);
    }
  }
}

if (detected_version != "unknown") {
  cpe = "cpe:/a:communigate:communigate_pro:" + detected_version;
} else {
  cpe = "cpe:/a:communigate:communigate_pro";
}

# HTTP
if (http_ports = get_kb_list("communigatepro/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(S) on port " + port + '/tcp\n';

    concluded = get_kb_item("communigatepro/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from: ' + concluded + '\n';

    register_product(cpe: cpe, location: port + '/tcp', port: port, service: "www");
  }
}

# SMTP
if (smtp_ports = get_kb_list("communigatepro/smtp/port")) {
  foreach port (smtp_ports) {
    extra += "SMTP on port " + port + '/tcp\n';

    concluded = get_kb_item("communigatepro/smtp/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from: ' + concluded + '\n';

    register_product(cpe: cpe, location: port + '/tcp', port: port, service: "smtp");
  }
}

# IMAP
if (imap_ports = get_kb_list("communigatepro/imap/port")) {
  foreach port (imap_ports) {
    extra += "IMAP on port " + port + '/tcp\n';

    concluded = get_kb_item("communigatepro/imap/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from: ' + concluded + '\n';

    register_product(cpe: cpe, location: port + '/tcp', port: port, service: "imap");
  }
}

report = build_detection_report(app: "CommuniGate Pro", version: version, install: "/", cpe: cpe);
if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
