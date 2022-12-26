# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:digium:asterisk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127001");
  script_version("2022-12-05T10:11:03+0000");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-03-08 02:05:15 +0000 (Tue, 08 Mar 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-27 14:45:00 +0000 (Wed, 27 Apr 2022)");

  script_cve_id("CVE-2022-26651");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk SQLi Vulnerability (AST-2022-003)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_mandatory_keys("Asterisk-PBX/Installed");

  script_tag(name:"summary", value:"Asterisk is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If input is provided to func_odbc which includes backslashes
  it is possible for func_odbc to construct a broken SQL query and the SQL query to fail.");

  script_tag(name:"affected", value:"Asterisk Open Source 16.x, 18.x, 19.x and 16.x Certified
  Asterisk");

  script_tag(name:"solution", value:"Update to version 16.25.2, 18.11.2, 19.3.2, 16.8-cert14 or
  later.");

  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2022-003.html");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^16\.") {
  if (version =~ "^16\.[0-9]cert") {
    if (revcomp(a: version, b: "16.8cert14") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "16.8-cert14");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "16.25.2")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "16.25.2");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version_in_range(version: version, test_version: "18.0", test_version2: "18.11.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.11.2");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

if (version_in_range(version: version, test_version: "19.0", test_version2: "19.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "19.3.2");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

exit(99);
