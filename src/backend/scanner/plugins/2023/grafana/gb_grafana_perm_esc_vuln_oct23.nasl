# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:grafana:grafana";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170605");
  script_version("2023-10-18T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-10-18 05:05:17 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-16 14:33:28 +0000 (Mon, 16 Oct 2023)");
  script_tag(name:"cvss_base", value:"8.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:P");

  script_cve_id("CVE-2023-4822");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: affects only instances with more than one organisation, and with RBAC enabled (prior to 10.0.0)

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana 8.x < 9.4.17, 9.5.x < 9.5.13, 9.6.x < 10.0.9, 10.1.x < 10.1.5 Cross-Organization Permission Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to a cross-organization permission escalation
  by an organization administrator vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Vulnerable versions of Grafana are incorrectly assessing
  permissions to update cross-organization roles and role assignments. Therefore users with
  administrator permissions in one organization can change cross-organization role permissions and
  cross-organization role assignments.

  This vulnerability impacts instances with more than one organization running Grafana Enterprise
  versions.

  No Grafana Cloud instances are impacted because the platform is limited to a single organization.");

  script_tag(name:"impact", value:"If exploited, an attacker who has the Organization Admin role in
  any organization can elevate their permissions across all organizations, elevate other users'
  permissions in all organizations, or limit other users' permissions in all organizations.

  The vulnerability, however, does not allow the attacker to become a member of an organization that
  they are not already a member of, nor can they add any other user to an organization that the
  attacker is not a member of already.");

  script_tag(name:"affected", value:"Grafana version 8.x prior to 9.4.17, 9.5.x prior to 9.5.13,
  9.6.x prior to 10.0.9 and 10.1.x prior to 10.1.5.

  Versions between 8.0.0 and 10.0.0 are only vulnerable if role-based access control (RBAC) is
  enabled.");

  script_tag(name:"solution", value:"Update to version 9.4.17, 9.5.13, 10.0.9, 10.1.5 or later.");

  script_xref(name:"URL", value:"https://grafana.com/blog/2023/10/13/grafana-security-release-new-versions-of-grafana-with-a-medium-severity-security-fix-for-cve-2023-4822/");

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

if (version_in_range_exclusive(version: version, test_version_lo: "8.0.0", test_version_up: "9.4.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.5.0", test_version_up: "9.5.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.6.0", test_version_up: "10.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.1.0", test_version_up: "10.1.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}


exit(0);
