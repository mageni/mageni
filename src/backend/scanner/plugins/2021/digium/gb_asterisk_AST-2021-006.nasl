# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.145527");
  script_version("2021-03-09T06:55:12+0000");
  script_tag(name:"last_modification", value:"2021-03-09 11:15:36 +0000 (Tue, 09 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-09 06:46:45 +0000 (Tue, 09 Mar 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_cve_id("CVE-2019-15297");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk DoS Vulnerability (AST-2021-006)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_mandatory_keys("Asterisk-PBX/Installed");

  script_tag(name:"summary", value:"Asterisk is prone to a denial of service vulnerability when negotiating
  T.38 with a zero port.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When Asterisk sends a re-invite initiating T.38 faxing and the endpoint
  responds with a m=image line and zero port, a crash will occur in Asterisk. This is a re-occurrence of
  AST-2019-004.");

  script_tag(name:"affected", value:"Asterisk Open Source 16.x, 17.x, 18.x and 16.x Certified Asterisk.");

  script_tag(name:"solution", value:"Update to version 16.16.2, 17.9.3, 18.2.2, 16.8-cert7 or later.");

  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2021-006.html");

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
  if (version =~ "^16\.[0-9]+cert") {
    if (revcomp(a: version, b: "16.8cert7") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "16.8-cert7");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "16.16.2")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "16.16.2");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version_in_range(version: version, test_version: "17.0", test_version2: "17.9.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "17.9.3");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

if (version_in_range(version: version, test_version: "18.0", test_version2: "18.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.2.2");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

exit(99);
