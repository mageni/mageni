# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127690");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-01 08:26:41 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal DoS Vulnerability (SA-CORE-2024-001) - Linux");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Drupal is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Comment module allows users to reply to comments.
  In certain cases, an attacker could make comment reply requests that would trigger a
  denial of service (DoS).");

  script_tag(name:"affected", value:"Drupal versions 8.x prior to 10.1.8, 10.2.x prior to
  10.2.2.");

  script_tag(name:"solution", value:"Update to version 10.1.8, 10.2.2, or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2024-001");

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

if( version_in_range_exclusive (version: version, test_version_lo: "8.0.0", test_version_up: "10.1.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.1.8", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "10.2.0", test_version_up: "10.2.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.2.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
