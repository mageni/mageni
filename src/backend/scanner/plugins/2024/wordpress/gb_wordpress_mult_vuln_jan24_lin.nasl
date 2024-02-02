# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114317");
  script_version("2024-02-01T14:37:16+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:16 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-01-31 16:14:37 +0000 (Wed, 31 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Multiple Vulnerabilities (Jan 2024) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"WordPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - PHP File Upload bypass via Plugin Installer (requiring admin privileges)

  - Remote Code Execution (RCE) POP Chains vulnerability");

  script_tag(name:"affected", value:"WordPress version 6.4.3 and prior.");

  script_tag(name:"solution", value:"Update to version 4.1.40, 4.2.37, 4.3.33, 4.4.32, 4.5.31,
  4.6.28, 4.7.28, 4.8.24, 4.9.25, 5.0.21, 5.1.18, 5.2.20, 5.3.17, 5.4.15, 5.5.14, 5.6.13, 5.7.11,
  5.8.9, 5.9.9, 6.0.7, 6.1.5, 6.2.4, 6.3.3, 6.4.3 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/news/2024/01/wordpress-6-4-3-maintenance-and-security-release/");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2024/01/the-wordpress-6-4-3-security-update-what-you-need-to-know/");

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

if (version_is_less(version: version, test_version: "4.1.40")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.40", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.2", test_version_up: "4.2.37")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.37", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.3", test_version_up: "4.3.33")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.33", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.4", test_version_up: "4.4.32")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.32", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.5", test_version_up: "4.5.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.31", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.6", test_version_up: "4.6.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.28", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.7", test_version_up: "4.7.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.28", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.8", test_version_up: "4.8.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.9", test_version_up: "4.9.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.25", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.0.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.1", test_version_up: "5.1.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.2", test_version_up: "5.2.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.3", test_version_up: "5.3.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.4", test_version_up: "5.4.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.5", test_version_up: "5.5.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.6", test_version_up: "5.6.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.7", test_version_up: "5.7.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.8", test_version_up: "5.8.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.8.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.9", test_version_up: "5.9.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.9.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.0", test_version_up: "6.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.1", test_version_up: "6.1.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.2", test_version_up: "6.2.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.3", test_version_up: "6.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.3.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.4", test_version_up: "6.4.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.4.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
