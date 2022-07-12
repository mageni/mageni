# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100795");
  script_version("2020-03-11T12:04:13+0000");
  script_tag(name:"last_modification", value:"2020-03-12 11:06:29 +0000 (Thu, 12 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-10 06:19:30 +0000 (Tue, 10 Mar 2020)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache Derby Detection Consolidation");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_apache_derby_drda_detect.nasl");
  script_mandatory_keys("apache/derby/detected");

  script_tag(name:"summary", value:"Reports all found Apache Derby installations including their version and location.");

  script_xref(name:"URL", value:"http://db.apache.org/derby/");

  exit(0);
}

if (!get_kb_item("apache/derby/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("drda")) {
  version_list = get_kb_list("apache/derby/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:apache:derby:");
if (!cpe)
  cpe = "cpe:/a:apache:derby";

if (drda_ports = get_kb_list("apache/derby/drda/port")) {
  foreach port (drda_ports) {
    extra += 'DRDA on port ' + port + '/tcp\n';

    concluded = get_kb_item("apache/derby/drda/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "drda");
  }
}

report = build_detection_report(app: "Apache Derby", version: detected_version, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
