# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wp-slimstat:slimstat_analytics";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126023");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-03-22 11:15:00 +0000 (Wed, 22 Mar 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-23 18:51:00 +0000 (Thu, 23 Mar 2023)");

  script_cve_id("CVE-2023-0630");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Slimstat Analytics Plugin < 4.9.3.3 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-slimstat/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Slimstat Analytics' is prone to an SQL
  injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not prevent subscribers from rendering
  shortcodes that concatenates attributes directly into an SQL query.");

  script_tag(name:"affected", value:"WordPress Slimstat Analytics plugin prior to version 4.9.3.3.");

  script_tag(name:"solution", value:"Update to version 4.9.3.3 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/b82bdd02-b699-4527-86cc-d60b56ab0c55");

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

if( version_is_less( version: version, test_version: "4.9.3.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.9.3.3", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
