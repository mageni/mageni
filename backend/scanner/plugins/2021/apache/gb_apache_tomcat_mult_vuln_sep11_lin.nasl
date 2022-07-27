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

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147036");
  script_version("2021-10-29T14:03:48+0000");
  script_tag(name:"last_modification", value:"2021-11-01 11:21:25 +0000 (Mon, 01 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-10-29 11:01:18 +0000 (Fri, 29 Oct 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2011-1184", "CVE-2011-5062", "CVE-2011-5063", "CVE-2011-5064",
                "CVE-2011-2204", "CVE-2011-2526", "CVE-2011-2729", "CVE-2011-3190");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat 5.5.x < 5.5.34 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2011-1184, CVE-2011-5062, CVE-2011-5063, CVE-2011-5064: Multiple weaknesses in HTTP DIGEST
  authentication

  - CVE-2011-2204, CVE-2011-2526, CVE-2011-2729: Information disclosure

  - CVE-2011-3190: Authentication bypass and information disclosure");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Tomcat version 5.5.x through 5.5.33.");

  script_tag(name:"solution", value:"Update to version 5.5.34 or later.");

  script_xref(name:"URL", value:"https://tomcat.apache.org/security-5.html");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "5.5.0", test_version2: "5.5.33")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.34", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
