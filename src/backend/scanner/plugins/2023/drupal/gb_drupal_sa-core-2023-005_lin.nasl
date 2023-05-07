# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149586");
  script_version("2023-04-27T12:17:38+0000");
  script_tag(name:"last_modification", value:"2023-04-27 12:17:38 +0000 (Thu, 27 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-27 03:00:47 +0000 (Thu, 27 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2023-31250");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal Access Bypass Vulnerability (SA-CORE-2023-005) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Drupal is prone to an access bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The file download facility doesn't sufficiently sanitize file
  paths in certain situations. This may result in users gaining access to private files that they
  should not have access to.");

  script_tag(name:"affected", value:"Drupal version 7.x, 9.4.x, 9.5.x and 10.0.x.");

  script_tag(name:"solution", value:"Update to version 7.96, 9.4.14, 9.5.8, 10.0.8 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2023-005");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "7.96")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.96", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.4.0", test_version_up: "9.4.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.5.0", test_version_up: "9.5.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0", test_version_up: "10.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
