# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:richplugins:plugin_for_google_reviews";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127429");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-05-15 12:08:03 +0000 (Mon, 15 May 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-23 13:20:00 +0000 (Wed, 23 Nov 2022)");

  script_cve_id("CVE-2022-45369");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Plugin for Google Reviews Plugin < 2.2.3 Broken Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/widget-google-reviews/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Plugin for Google Reviews' is prone to a
  broken access control vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Authorized broken access control");

  script_tag(name:"affected", value:"WordPress Plugin for Google Reviews plugin prior to version 2.2.3.");

  script_tag(name:"solution", value:"Update to version 2.2.3 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/widget-google-reviews/wordpress-plugin-for-google-reviews-plugin-2-2-2-auth-broken-access-control-vulnerability");

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

if( version_is_less( version: version, test_version: "2.2.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
