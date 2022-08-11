###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_isc_bind_tsig_auth_vuln.nasl 13654 2019-02-14 07:51:59Z mmartin $
#
# ISC BIND Security Bypass Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:isc:bind";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106937");
  script_version("$Revision: 13654 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 08:51:59 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-07-11 11:31:58 +0700 (Tue, 11 Jul 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2017-3143");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ISC BIND Security Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("bind_version.nasl");
  script_mandatory_keys("ISC BIND/installed");

  script_tag(name:"summary", value:"A flaw was found in the way BIND handled TSIG authentication for dynamic
updates. A remote attacker able to communicate with an authoritative BIND server could use this flaw to
manipulate the contents of a zone, by forging a valid TSIG or SIG(0) signature for a dynamic update request.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"ISC BIND versions 9.4.0-9.8.8, 9.9.0-9.9.10-P1, 9.10.0-9.10.5-P1,
9.11.0-9.11.1-P1, 9.9.3-S1-9.9.10-S2 and 9.10.5-S1-9.10.5-S2");

  script_tag(name:"solution", value:"Update to version 9.9.10-P2, 9.10.5-P2, 9.11.1-P2, 9.9.10-S3, 9.10.5-S3
or later.");

  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01503/0");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!info = get_app_version_and_proto(cpe: CPE, port: port))
  exit(0);

version = info["version"];
proto = info["proto"];

if (version =~ "9\.(9|10)\.[0-9]+\.S[0-9]") {
  if (version_is_less(version: version, test_version: "9.9.10.S3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.9.10-S3");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.10.5.S1", test_version2: "9.10.5.S2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.10.5-S3");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}
else {
  if (version_in_range(version: version, test_version: "9.4.0", test_version2: "9.8.8") ||
      version_in_range(version: version, test_version: "9.9.0", test_version2: "9.9.10.P1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.9.10-P2");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.10.0", test_version2: "9.10.5-P1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.10.5-P2");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.11.0", test_version2: "9.11.1-P1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.11.1-P2");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
