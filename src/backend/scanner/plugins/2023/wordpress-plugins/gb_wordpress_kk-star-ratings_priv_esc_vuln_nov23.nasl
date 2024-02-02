# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kk_star_ratings_project:kk_star_ratings";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124484");
  script_version("2023-12-06T05:06:11+0000");
  script_tag(name:"last_modification", value:"2023-12-06 05:06:11 +0000 (Wed, 06 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-11-29 10:05:46 +0000 (Wed, 29 Nov 2023)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-01 19:53:00 +0000 (Fri, 01 Dec 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-4642");

  script_name("WordPress kk Star Ratings Plugin < 5.4.6 Race Condition Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/kk-star-ratings/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'kk Star Ratings' is prone to a race
  condition vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not implement atomic operations, allowing one
  user vote multiple times on a poll due to a Race Condition.");

  script_tag(name:"affected", value:"WordPress kk Star Ratings plugin prior to version 5.4.6.");

  script_tag(name:"solution", value:"Update to version 5.4.6 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/6f481d34-6feb-4af2-914c-1f3288f69207");

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

if( version_is_less( version: version, test_version: "5.4.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.4.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
