# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpdeveloper:reviewx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126522");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-09-12 08:08:12 +0000 (Tue, 12 Sep 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-03 16:43:00 +0000 (Fri, 03 Mar 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-26325");

  script_name("WordPress ReviewX Plugin < 1.6.9 SQL Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/reviewx/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'ReviewX' is prone to an SQL injection
  (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not properly sanitise and escape the
  filterValue and selectedColumns parameters before using them in SQL statements via the
  rx_export_review AJAX action available to any authenticated users, leading to a SQL injection
  exploitable by users with a role as low as subscriber.");

  script_tag(name:"affected", value:"WordPress ReviewX plugin prior to version 1.6.9.");

  script_tag(name:"solution", value:"Update to version 1.6.9 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/reviewx/reviewx-multi-criteria-rating-reviews-for-woocommerce-167-authenticated-subscriber-sql-injection");

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

if( version_is_less( version: version, test_version: "1.6.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.6.9", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
