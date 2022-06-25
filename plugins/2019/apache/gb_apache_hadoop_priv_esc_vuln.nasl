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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.#

CPE = "cpe:/a:apache:hadoop";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142482");
  script_version("2019-06-03T03:48:39+0000");
  script_tag(name:"last_modification", value:"2019-06-03 03:48:39 +0000 (Mon, 03 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-03 03:35:42 +0000 (Mon, 03 Jun 2019)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2018-8029");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Hadoop Privilege Escalation Vulnerability (CVE-2018-8029)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_hadoop_detect.nasl");
  script_mandatory_keys("Apache/Hadoop/Installed");

  script_tag(name:"summary", value:"Apache Hadoop is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host");

  script_tag(name:"insight", value:"A user who can escalate to yarn user can possibly run arbitrary commands as
  root user.");

  script_tag(name:"affected", value:"Apache Hadoop versions 3.0.0-alpha1 to 3.1.0, 2.9.0 to 2.9.1 and 2.2.0 to
  2.8.4.");

  script_tag(name:"solution", value:"Upgrade to version 2.8.5, 2.9.2, 3.1.1 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/17084c09e6dedf60efe08028b429c92ffd28aacc28454e4fa924578a@%3Cgeneral.hadoop.apache.org%3E");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (version_in_range(version: version, test_version: "2.2.0", test_version2: "2.8.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.8.5", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.9.0", test_version2: "2.9.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.9.2", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "3\." && version_is_less(version: version, test_version: "3.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
