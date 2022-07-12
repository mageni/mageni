##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kamailio_heap_overflow_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# Kamailio Heap Overflow Vulnerability
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

CPE = "cpe:/a:kamailio:kamailio";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140938");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-04-03 15:52:17 +0700 (Tue, 03 Apr 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-8828");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Kamailio Heap Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_kamailio_detect.nasl");
  script_mandatory_keys("kamailio/installed");

  script_tag(name:"summary", value:"Kamailio is prone to a heap overflow vulnerability which may result in a
denial of service condition.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A specially crafted REGISTER message with a malformed branch or From tag
triggers an off-by-one heap overflow.");

  script_tag(name:"affected", value:"Kamailio versions 4.4.x, 5.0.x and 5.1.x");

  script_tag(name:"solution", value:"Update to version 4.4.7, 5.0.6, 5.1.2 or later.");

  script_xref(name:"URL", value:"https://www.kamailio.org/w/2018/03/kamailio-security-announcement-tmx-lcr/");
  script_xref(name:"URL", value:"https://github.com/EnableSecurity/advisories/tree/master/ES2018-05-kamailio-heap-overflow");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if (version_is_less(version: version, test_version: "4.4.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.7");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0", test_version2: "5.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.6");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.1", test_version2: "5.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.2");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(0);
