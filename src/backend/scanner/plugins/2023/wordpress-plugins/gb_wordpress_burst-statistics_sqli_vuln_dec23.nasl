# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:burst-statistics:burst_statistics";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127657");
  script_version("2023-12-15T16:10:08+0000");
  script_tag(name:"last_modification", value:"2023-12-15 16:10:08 +0000 (Fri, 15 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-14 08:08:03 +0000 (Thu, 14 Dec 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-12 15:50:00 +0000 (Tue, 12 Dec 2023)");

  script_cve_id("CVE-2023-5761");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Burst Statistics - Privacy-Friendly Analytics for WordPress Plugin 1.4.x < 1.5.0 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/burst-statistics/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Burst Statistics - Privacy-Friendly
  Analytics for WordPress' is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Unauthenticated attackers are able to append additional
  SQL queries into already existing queries that can be used to extract sensitive information from
  the database.");

  script_tag(name:"insight", value:"Insufficient escaping on the user supplied parameter and lack
  of sufficient preparation on the existing SQL query.");

  script_tag(name:"affected", value:"WordPress Burst Statistics - Privacy-Friendly Analytics for
  WordPress plugin version 1.4.x prior to 1.5.0.");

  script_tag(name:"solution", value:"Update to version 1.5.0 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/30f8419c-c7b9-4c68-a845-26c0308d76f3");

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

if( version_in_range_exclusive( version: version, test_version_lo: "1.4.0", test_version_up: "1.5.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.5.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
