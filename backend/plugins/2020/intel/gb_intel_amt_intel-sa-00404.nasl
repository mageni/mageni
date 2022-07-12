# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/h:intel:active_management_technology";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144540");
  script_version("2020-09-09T08:28:48+0000");
  script_tag(name:"last_modification", value:"2020-09-09 09:59:16 +0000 (Wed, 09 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-06-17 04:41:17 +0000 (Wed, 17 Jun 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2020-8758");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Intel Active Management Technology Privilege Escalation Vulnerability (INTEL-SA-00404)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_intel_amt_webui_detect.nasl");
  script_mandatory_keys("intel_amt/installed");

  script_tag(name:"summary", value:"Intel Active Management Technology (AMT) is prone to a privilege escalation vulnerability.");

  script_tag(name:"insight", value:"Improper buffer restrictions in network subsystem in provisioned Intel AMT may
  allow an unauthenticated user to potentially enable escalation of privilege via network access. On
  un-provisioned systems, an authenticated user may potentially enable escalation of privilege via local access.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Intel Active Management Technology prior to versions 11.8.79, 11.12.79,
  11.22.79, 12.0.68 or 14.0.39.");

  script_tag(name:"solution", value:"Update to version 11.8.79, 11.12.79, 11.22.79, 12.0.68, 14.0.39 or later.");

  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00404.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "11.8.79")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.8.79", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.10", test_version2: "11.12.78")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.12.79", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.20", test_version2: "11.22.78")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.22.79", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "12.0", test_version2: "12.0.67")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.0.68", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "14.0", test_version2: "14.0.38")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.0.39", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
