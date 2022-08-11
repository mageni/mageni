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

CPE = "cpe:/a:mantisbt:mantisbt";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145168");
  script_version("2021-01-15T07:17:06+0000");
  script_tag(name:"last_modification", value:"2021-01-15 11:06:40 +0000 (Fri, 15 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-15 07:16:25 +0000 (Fri, 15 Jan 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2020-28413", "CVE-2020-35849");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MantisBT < 2.24.4 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("mantis_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mantisbt/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"MantisBT is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - SQL Injection can occur in the parameter 'access' of the mc_project_get_users function through the API SOAP (CVE-2020-28413)

  - Incorrect access check in bug_revision_view_page.php allows an unprivileged attacker to view the Summary
    field of private issues, as well as bugnotes revisions, gaining access to potentially confidential
    information via the bugnote_id parameter (CVE-2020-35849)");

  script_tag(name:"affected", value:"MantisBT versions 2.24.3 and probably prior.");

  script_tag(name:"solution", value:"Update to version 2.24.4 or later.");

  script_xref(name:"URL", value:"https://www.mantisbt.org/bugs/view.php?id=27495");
  script_xref(name:"URL", value:"https://www.mantisbt.org/bugs/view.php?id=27370");
  script_xref(name:"URL", value:"https://ethicalhcop.medium.com/cve-2020-28413-blind-sql-injection-en-mantis-bug-tracker-2-24-3-api-soap-54238f8e046d");

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

if (version_is_less(version: version, test_version: "2.24.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.24.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
