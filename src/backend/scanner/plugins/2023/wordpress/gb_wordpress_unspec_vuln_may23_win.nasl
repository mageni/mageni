# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104757");
  script_version("2023-05-24T09:09:06+0000");
  script_tag(name:"last_modification", value:"2023-05-24 09:09:06 +0000 (Wed, 24 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-22 12:37:00 +0000 (Mon, 22 May 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Unspecified Vulnerability (May 2023) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"WordPress is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The update block themes parsing shortcodes in user-generated
  data.");

  script_tag(name:"affected", value:"WordPress version 6.2.1 and prior.");

  script_tag(name:"solution", value:"Update to version 5.9.7, 6.0.5, 6.1.3, 6.2.2 or later.

  Note: 5.8.x and previous branches appear to have not received a fix. According to the advisory,
  the vendor may not provide a fix:

  'All versions since WordPress 5.9 have also been updated.'");

  script_xref(name:"URL", value:"https://wordpress.org/news/2023/05/wordpress-6-2-2-security-release/");

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

if (version_is_less(version: version, test_version: "5.9.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.9.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.0", test_version_up: "6.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.1", test_version_up: "6.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.2", test_version_up: "6.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
