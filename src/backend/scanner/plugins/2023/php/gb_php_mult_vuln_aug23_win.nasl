# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170530");
  script_version("2023-08-04T16:09:15+0000");
  script_tag(name:"last_modification", value:"2023-08-04 16:09:15 +0000 (Fri, 04 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-02-15 13:46:36 +0000 (Wed, 15 Feb 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2023-3823", "CVE-2023-3824");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 8.0.30, 8.1.x < 8.1.22 Security Update - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-3823: Fixed bug GHSA-3qrf-m4j2-pcrr (Security issue with external entity loading in XML
  without enabling it)

  - CVE-2023-3824: Fixed bug GHSA-jqcx-ccgc-xwhv (Buffer mismanagement in phar_dir_read())");

  script_tag(name:"affected", value:"PHP prior to version 8.0.30 and 8.1.x prior to 8.1.22.");

  script_tag(name:"solution", value:"Update to version 8.0.30, 8.1.22 or later.");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.1.22");
  script_xref(name:"URL", value:"https://github.com/php/php-src/blob/PHP-8.0.30/NEWS#L3-L11");

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

if (version_is_less(version: version, test_version: "8.0.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.30", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.1", test_version_up: "8.1.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
