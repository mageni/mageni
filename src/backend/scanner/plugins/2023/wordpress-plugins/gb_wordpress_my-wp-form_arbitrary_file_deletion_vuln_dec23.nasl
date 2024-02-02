# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:web-soudan:mw_wp_form";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126555");
  script_version("2023-12-26T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-26 05:05:23 +0000 (Tue, 26 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-08-29 08:03:12 +0000 (Tue, 29 Aug 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-20 04:13:00 +0000 (Wed, 20 Dec 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-6559");

  script_name("WordPress The MW WP Form Plugin < 5.0.4 Arbitrary File Deletion Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/mw-wp-form/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'The MW WP Form' is prone to an
  arbitrary file deletion vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin not properly validating the path of an upload
  file prior to deleting it.");

  script_tag(name:"affected", value:"WordPress The MW WP Form plugin prior to version 5.0.4.");

  script_tag(name:"solution", value:"Update to version 5.0.4 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/412d555c-9bbd-42f5-8020-ccfc18755a79");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "5.0.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.0.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
