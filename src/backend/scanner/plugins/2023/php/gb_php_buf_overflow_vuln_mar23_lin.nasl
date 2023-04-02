# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104644");
  script_version("2023-03-24T10:09:03+0000");
  script_tag(name:"last_modification", value:"2023-03-24 10:09:03 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-21 10:40:23 +0000 (Tue, 21 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2022-4900");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 8.0.22, 8.1.x < 8.1.9 Security Update - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Fixed potential overflow for the builtin server via the
  PHP_CLI_SERVER_WORKERS environment variable.");

  script_tag(name:"affected", value:"PHP versions prior to 8.0.22 and 8.1.x prior to 8.1.9.");

  script_tag(name:"solution", value:"Update to version 8.0.22, 8.1.9, 8.2.0 or later.");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.2.0");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.1.9");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.0.22");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/8989");
  script_xref(name:"URL", value:"https://github.com/php/php-src/pull/9000");
  script_xref(name:"URL", value:"https://github.com/php/php-src/commit/789a37f14405e2d1a05a76c9fb4ed2d49d4580d5");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2179880");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "8.0.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.22/8.1.9/8.2.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.1", test_version_up: "8.1.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.9/8.2.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
