# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104753");
  script_version("2023-05-22T12:17:59+0000");
  script_tag(name:"last_modification", value:"2023-05-22 12:17:59 +0000 (Mon, 22 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-17 15:07:14 +0000 (Wed, 17 May 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2023-2745");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Multiple Vulnerabilities (May 2023) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"WordPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - No CVE: Block themes parsing shortcodes in user generated data

  - No CVE: A CSRF issue updating attachment thumbnails

  - No CVE: A flaw allowing XSS via open embed auto discovery

  - No CVE: Bypassing of KSES sanitization in block attributes for low privileged users

  - CVE-2023-2745: A path traversal issue via translation files");

  script_tag(name:"affected", value:"WordPress version 6.2.0 and prior.");

  script_tag(name:"solution", value:"Update to version 4.1.38, 4.2.35, 4.3.31, 4.4.30, 4.5.29,
  4.6.26, 4.7.26, 4.8.22, 4.9.23, 5.0.19, 5.1.16, 5.2.18, 5.3.15, 5.4.13, 5.5.12, 5.6.11, 5.7.9,
  5.8.7, 5.9.6, 6.0.4, 6.1.2, 6.2.1 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2023/05/wordpress-core-6-2-1-security-maintenance-release-what-you-need-to-know/");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-621-directory-traversal");

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

if (version_is_less(version: version, test_version: "4.1.38")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.38", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.2", test_version_up: "4.2.35")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.35", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.3", test_version_up: "4.3.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.31", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.4", test_version_up: "4.4.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.30", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.5", test_version_up: "4.5.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.6", test_version_up: "4.6.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.26", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.7", test_version_up: "4.7.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.26", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.8", test_version_up: "4.8.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.9", test_version_up: "4.9.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.0.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.1", test_version_up: "5.1.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.2", test_version_up: "5.2.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.3", test_version_up: "5.3.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.4", test_version_up: "5.4.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.5", test_version_up: "5.5.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.6", test_version_up: "5.6.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.7", test_version_up: "5.7.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.8", test_version_up: "5.8.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.8.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.9", test_version_up: "5.9.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.9.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.0", test_version_up: "6.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.1", test_version_up: "6.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.2", test_version_up: "6.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
