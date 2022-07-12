###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_isc_bind_dos_vuln_jan18_win.nasl 13654 2019-02-14 07:51:59Z mmartin $
#
# ISC BIND DoS Vulnerability - Jan17 (Windows)
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

CPE = 'cpe:/a:isc:bind';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140696");
  script_version("$Revision: 13654 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 08:51:59 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-01-17 15:42:36 +0700 (Wed, 17 Jan 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2017-3145");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ISC BIND DoS Vulnerability - Jan17 (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("bind_version.nasl", "os_detection.nasl");
  script_mandatory_keys("ISC BIND/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"BIND is improperly sequencing cleanup operations on upstream recursion fetch
contexts, leading in some cases to a use-after-free error that can trigger an assertion failure and crash in
named.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"ISC BIND 9 9.9.9-P8 to 9.9.11, 9.10.4-P8 to 9.10.6, 9.11.0-P5 to 9.11.2,
9.9.9-S10 to 9.9.11-S1, 9.10.5-S1 to 9.10.6-S1, and 9.12.0a1 to 9.12.0rc1 on Windows.");

  script_tag(name:"solution", value:"Update to version 9.9.11-S2, 9.10.6-S2, 9.9.11-P1, 9.10.6-P1, 9.11.2-P1,
9.12.0rc2 or later.");

  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01542");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if (version !~ "^9\.")
  exit(99);

if (version =~ "9\.(9|10)\.[0-9]\.S[0-9]") {
  if (version_in_range(version: version, test_version: "9.9.9.S10", test_version2: "9.9.11.S1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.9.11-S2");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.10.5.S1", test_version2: "9.10.6.S1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.10.6-S2");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if (version_in_range(version: version, test_version: "9.9.9.P8", test_version2: "9.9.11")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.9.11-P1");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.10.4.P8", test_version2: "9.10.6")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.10.6.P1");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.11.0.P5", test_version2: "9.11.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.11.2-P1");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if ((revcomp(a: version, b: "9.12.0a1") >= 0) && (revcomp(a: version, b: "9.12.0rc2") < 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.12.0rc2");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(0);
