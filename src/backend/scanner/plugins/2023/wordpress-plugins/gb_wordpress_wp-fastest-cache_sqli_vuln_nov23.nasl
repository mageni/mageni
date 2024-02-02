# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpfastestcache:wp_fastest_cache";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127625");
  script_version("2023-12-12T05:05:39+0000");
  script_tag(name:"last_modification", value:"2023-12-12 05:05:39 +0000 (Tue, 12 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-11-17 08:35:51 +0000 (Fri, 17 Nov 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-08 14:39:00 +0000 (Fri, 08 Dec 2023)");

  script_cve_id("CVE-2023-6063");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Fastest Cache Plugin < 1.2.2 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-fastest-cache/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Fastest Cache' is prone to an
  SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not properly sanitise and escape a parameter
  before using it in a SQL statement, leading to a SQL injection exploitable by unauthenticated
  users.");

  script_tag(name:"affected", value:"WordPress Fastest Cache plugin prior to version 1.2.2.");

  script_tag(name:"solution", value:"Update to version 1.2.2 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/30a74105-8ade-4198-abe2-1c6f2967443e/");

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

if( version_is_less( version: version, test_version: "1.2.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.2.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
