###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asterisk_AST-2018-009.nasl 12889 2018-12-28 07:52:20Z mmartin $
#
# Asterisk DoS Vulnerability (AST-2018-009)
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

CPE = 'cpe:/a:digium:asterisk';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141496");
  script_version("$Revision: 12889 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-28 08:52:20 +0100 (Fri, 28 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-09-21 11:47:14 +0700 (Fri, 21 Sep 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2018-17281");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk DoS Vulnerability (AST-2018-009)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_mandatory_keys("Asterisk-PBX/Installed");

  script_tag(name:"summary", value:"Asterisk is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is a stack overflow vulnerability in the res_http_websocket.so module
of Asterisk that allows an attacker to crash Asterisk via a specially crafted HTTP request to upgrade the
connection to a websocket. The attacker's request causes Asterisk to run out of stack space and crash.");

  script_tag(name:"affected", value:"Asterisk Open Source 13.x, 14.x, 15.x and Certified Asterisk 13.21.");

  script_tag(name:"solution", value:"Upgrade to Version 13.23.1, 14.7.8, 15.6.1, 13.21-cert3 or
later.");

  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2018-009.html");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^13\.") {
  if (version =~ "13\.21cert") {
    if (revcomp(a: version, b: "13.21cert3") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.21-cert3");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "13.23.1")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.23.1");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version =~ "^14\.") {
  if (version_is_less(version: version, test_version: "14.7.8")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.7.8");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

if (version =~ "^15\.") {
  if (version_is_less(version: version, test_version: "15.6.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.6.1");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

exit(0);
