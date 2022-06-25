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
  script_oid("1.3.6.1.4.1.25623.1.0.117257");
  script_version("2021-03-18T07:02:00+0000");
  script_tag(name:"last_modification", value:"2021-03-18 11:03:57 +0000 (Thu, 18 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-18 06:53:06 +0000 (Thu, 18 Mar 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2013-6357"); # nb: The CVE is DISPUTED but the vulnerability is valid and underestimated by the vendor.

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Apache Tomcat <= 5.5.25 CSRF Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a cross-site request forgery
  (CSRF) vulnerability.");

  script_tag(name:"insight", value:"The CSRF vulnerability affecting the Manager
  application of Apache Tomcat. An attacker can trick an administrator to perform the
  following activities:

  - stop an existing application

  - undeploy an existing application

  - deploy a new application");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"affected", value:"Apache Tomcat through 5.5.25.");

  script_tag(name:"solution", value:"No known solution was made available for at least one
  year since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.webapp-security.com/wp-content/uploads/2013/11/Apache-Tomcat-5.5.25-CSRF-Vulnerabilities.txt");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/29435");

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

if (version_is_less_equal(version: version, test_version: "5.5.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.25", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
