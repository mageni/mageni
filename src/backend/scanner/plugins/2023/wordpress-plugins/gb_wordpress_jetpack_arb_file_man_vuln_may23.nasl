# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:automattic:jetpack";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127450");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-06-02 08:08:03 +0000 (Fri, 02 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-03 19:26:00 +0000 (Mon, 03 Jul 2023)");

  script_cve_id("CVE-2023-2996");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress JetPack Plugin Arbitrary File Manipulation Vulnerability (CVE-2023-2996)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/jetpack/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'JetPack' is prone to an
  arbitrary file manipulation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not validate uploaded files, allowing users
  with author roles or above to manipulate existing files on the site, deleting arbitrary files,
  and in rare cases achieve Remote Code Execution via phar deserialization.");

  script_tag(name:"affected", value:"See advisories for more details.");

  script_tag(name:"solution", value:"See advisories for more details.");

  script_xref(name:"URL", value:"https://jetpack.com/blog/jetpack-12-1-1-critical-security-update/");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/52d221bd-ae42-435d-a90a-60a5ae530663");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version: version, test_version_lo: "2.0.0", test_version_up: "2.0.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.0.9", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.1.0", test_version_up: "2.1.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.2.0", test_version_up: "2.2.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.10", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.3.0", test_version_up: "2.3.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.3.10", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.4.0", test_version_up: "2.4.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.4.7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.5.0", test_version_up: "2.5.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.5.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.6.0", test_version_up: "2.6.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.6.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.7.0", test_version_up: "2.7.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.7.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.8.0", test_version_up: "2.8.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.8.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.9.0", test_version_up: "2.9.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.9.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "3.0.0", test_version_up: "3.0.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.0.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "3.1.0", test_version_up: "3.1.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "3.2.0", test_version_up: "3.2.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "3.3.0", test_version_up: "3.3.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.3.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "3.4.0", test_version_up: "3.4.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.4.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "3.5.0", test_version_up: "3.5.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.5.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "3.6.0", test_version_up: "3.6.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.6.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}


if( version_in_range_exclusive( version: version, test_version_lo: "3.7.0", test_version_up: "3.7.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.7.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "3.8.0", test_version_up: "3.8.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.8.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "3.9.0", test_version_up: "3.9.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.9.9", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.0.0", test_version_up: "4.0.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.0.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.1.0", test_version_up: "4.1.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.1.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.2.0", test_version_up: "4.2.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.2.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.3.0", test_version_up: "4.3.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.3.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.4.0", test_version_up: "4.4.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.4.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.5.0", test_version_up: "4.5.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.5.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.6.0", test_version_up: "4.6.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.6.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.7.0", test_version_up: "4.7.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.7.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.8.0", test_version_up: "4.8.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.8.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.9.0", test_version_up: "4.9.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.9.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "5.0.0", test_version_up: "5.0.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.0.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "5.1.0", test_version_up: "5.1.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.1.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "5.2.0", test_version_up: "5.2.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.2.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "5.3.0", test_version_up: "5.3.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.3.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "5.4.0", test_version_up: "5.4.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.4.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "5.5.0", test_version_up: "5.5.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.5.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "5.6.0", test_version_up: "5.6.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.6.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "5.7.0", test_version_up: "5.7.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.7.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "5.8.0", test_version_up: "5.8.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.8.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "5.9.0", test_version_up: "5.9.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.9.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "6.0.0", test_version_up: "6.0.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.0.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "6.1.0", test_version_up: "6.1.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.1.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "6.2.0", test_version_up: "6.2.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.2.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "6.3.0", test_version_up: "6.3.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.3.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "6.4.0", test_version_up: "6.4.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.4.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "6.5.0", test_version_up: "6.5.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.5.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "6.6.0", test_version_up: "6.6.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.6.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "6.7.0", test_version_up: "6.7.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.7.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "6.8.0", test_version_up: "6.8.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.8.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "6.9.0", test_version_up: "6.9.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.9.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "7.0.0", test_version_up: "7.0.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.0.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "7.1.0", test_version_up: "7.1.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.1.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "7.2.0", test_version_up: "7.2.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.2.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "7.3.0", test_version_up: "7.3.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.3.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "7.4.0", test_version_up: "7.4.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.4.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "7.5.0", test_version_up: "7.5.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.5.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "7.6.0", test_version_up: "7.6.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.6.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "7.7.0", test_version_up: "7.7.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.7.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "7.8.0", test_version_up: "7.8.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.8.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "7.9.0", test_version_up: "7.9.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.9.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "8.0.0", test_version_up: "8.0.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.0.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "8.1.0", test_version_up: "8.1.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.1.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "8.2.0", test_version_up: "8.2.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.2.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "8.3.0", test_version_up: "8.3.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.3.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "8.4.0", test_version_up: "8.4.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.4.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "8.5.0", test_version_up: "8.5.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.5.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "8.6.0", test_version_up: "8.6.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.6.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "8.7.0", test_version_up: "8.7.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.7.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "8.8.0", test_version_up: "8.8.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.8.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "8.9.0", test_version_up: "8.9.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.9.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.0.0", test_version_up: "9.0.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.0.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.1.0", test_version_up: "9.1.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.1.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.2.0", test_version_up: "9.2.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.2.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.3.0", test_version_up: "9.3.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.3.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.4.0", test_version_up: "9.4.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.4.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.5.0", test_version_up: "9.5.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.5.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.6.0", test_version_up: "9.6.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.6.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.7.0", test_version_up: "9.7.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.7.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.8.0", test_version_up: "9.8.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.8.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.9.0", test_version_up: "9.9.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.9.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "10.0.0", test_version_up: "10.0.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.0.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "10.1.0", test_version_up: "10.1.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.1.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "10.2.0", test_version_up: "10.2.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.2.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "10.3.0", test_version_up: "10.3.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.3.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "10.4.0", test_version_up: "10.4.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.4.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "10.5.0", test_version_up: "10.5.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.5.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "10.6.0", test_version_up: "10.6.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.6.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "10.7.0", test_version_up: "10.7.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.7.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "10.8.0", test_version_up: "10.8.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.8.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "10.9.0", test_version_up: "10.9.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.9.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "11.0.0", test_version_up: "11.0.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.0.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "11.1.0", test_version_up: "11.1.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.1.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "11.2.0", test_version_up: "11.2.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.2.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "11.3.0", test_version_up: "11.3.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.3.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "11.4.0", test_version_up: "11.4.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.4.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "11.5.0", test_version_up: "11.5.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.5.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "11.6.0", test_version_up: "11.6.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.6.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "11.7.0", test_version_up: "11.7.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.7.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "11.8.0", test_version_up: "11.8.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.8.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "11.9.0", test_version_up: "11.9.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.9.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "12.0.0", test_version_up: "12.0.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "12.0.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "12.1.0", test_version_up: "12.1.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "12.1.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
