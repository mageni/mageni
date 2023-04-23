# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kriesi:enfold";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124300");
  script_version("2023-04-03T10:10:12+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:10:12 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-03-29 08:29:25 +0000 (Wed, 29 Mar 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2014-7297");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Enfold Theme Plugin < 3.0.1 Unknown Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_theme_http_detect.nasl");
  script_mandatory_keys("wordpress/theme/enfoldtheme/detected");

  script_tag(name:"summary", value:"The WordPress 'Enfold' theme is prone to an unknown vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The enfold WordPress theme was affected by an Unspecified Issue
  security vulnerability.");

  script_tag(name:"affected", value:"WordPress Enfold theme prior to version 3.0.1.");

  script_tag(name:"solution", value:"Update to version 3.0.1 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/9809");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"3.0.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.0.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
