# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:veronalabs:wp_statistics";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127378");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-03-10 07:55:09 +0000 (Fri, 10 Mar 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-31 15:34:00 +0000 (Fri, 31 Mar 2023)");

  script_cve_id("CVE-2022-38074", "CVE-2023-0955");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WP Statistics Plugin < 13.2.11 Multiple SQLi Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-statistics/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WP Statistics' is prone to multiple
  SQL injection (SQLi) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-38074: A malicious actor is able to interact with your database, including but not
  limited to stealing information.

  - CVE-2023-0955: The plugin does not escape a parameter, which could allow authenticated users to
  perform SQL Injection attacks.");

  script_tag(name:"affected", value:"WordPress WP Statistics plugin prior to version 13.2.11.");

  script_tag(name:"solution", value:"Update to version 13.2.11 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/18b7e93f-b038-4f28-918b-4015d62f0eb8");
  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/wp-statistics/wordpress-wp-statistics-plugin-13-2-10-multiple-authenticated-sql-injection-vulnerabilities");

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

if( version_is_less( version: version, test_version: "13.2.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "13.2.11", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
