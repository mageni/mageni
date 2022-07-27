# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

CPE = 'cpe:/a:digium:asterisk';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142585");
  script_version("2019-07-12T02:28:28+0000");
  script_tag(name:"last_modification", value:"2019-07-12 02:28:28 +0000 (Fri, 12 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-12 02:13:53 +0000 (Fri, 12 Jul 2019)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2019-12827", "CVE-2019-13161");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk Multiple DoS Vulnerabilities (AST-2019-002, AST-2019-003)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_mandatory_keys("Asterisk-PBX/Installed");

  script_tag(name:"summary", value:"Asterisk is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Asterisk is prone to multiple denial of service vulnerabilities:

  - Remote crash vulnerability with MESSAGE messages (CVE-2019-12827)

  - Remote Crash Vulnerability in chan_sip channel driver (CVE-2019-13161)");

  script_tag(name:"affected", value:"Asterisk Open Source 13.x, 15.x and 16.x and Certified Asterisk 13.21.");

  script_tag(name:"solution", value:"Upgrade to Version 13.27.1, 15.7.3, 16.4.1, 13.21-cert4 or later.");

  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2019-002.html");
  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2019-003.html");

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
    if (revcomp(a: version, b: "13.21cert4") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.21-cert4");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "13.27.1")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.27.1");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version =~ "^15\.") {
  if (version_is_less(version: version, test_version: "15.7.3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.7.3");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

if (version =~ "^16\.") {
  if (version_is_less(version: version, test_version: "16.4.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "16.4.1");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

exit(0);
