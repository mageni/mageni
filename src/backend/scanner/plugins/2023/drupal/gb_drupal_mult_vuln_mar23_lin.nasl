# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126390");
  script_version("2023-03-24T10:09:03+0000");
  script_tag(name:"last_modification", value:"2023-03-24 10:09:03 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-16 12:26:41 +0000 (Thu, 16 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal Multiple Vulnerabilities (SA-CORE-2023-002, SA-CORE-2023-003) - Linux");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Drupal is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - SA-CORE-2023-002: The Media module does not properly check entity access in some circumstances.

  - SA-CORE-2023-003: The URL of unpublished translations may be disclosed. When used in
  conjunction with a module like Pathauto, this may reveal the title of unpublished content.");

  script_tag(name:"affected", value:"Drupal versions starting from 8.0.0 and prior to 9.4.12, 9.5.x
  prior to 9.5.5 and 10.x prior to 10.0.5.");

  script_tag(name:"solution", value:"Update to version 9.4.12, 9.5.5, 10.0.5 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2023-002");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2023-003");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\.[0-9]+" ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive (version: version, test_version_lo: "8.0.0", test_version_up: "9.4.12" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.4.12", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.5.0", test_version_up: "9.5.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.5.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "10.0.0", test_version_up: "10.0.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.0.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
