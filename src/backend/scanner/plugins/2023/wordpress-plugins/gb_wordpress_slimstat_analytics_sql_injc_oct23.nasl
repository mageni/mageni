# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wp-slimstat:slimstat_analytics";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124451");
  script_version("2023-11-01T05:05:34+0000");
  script_tag(name:"last_modification", value:"2023-11-01 05:05:34 +0000 (Wed, 01 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-10-25 11:15:00 +0000 (Wed, 25 Oct 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-27 17:23:00 +0000 (Fri, 27 Oct 2023)");

  script_cve_id("CVE-2023-4598");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Slimstat Analytics Plugin < 5.0.10 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-slimstat/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Slimstat Analytics' is prone to an SQL
  injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin allows authenticated attackers with
  contributor-level and above permissions to append additional SQL queries into already existing
  queries that can be used to extract sensitive information from the database.");

  script_tag(name:"affected", value:"WordPress Slimstat Analytics plugin prior to version 5.0.10.");

  script_tag(name:"solution", value:"Update to version 5.0.10 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/07c0f5a5-3455-4f06-b481-f4d678309c50");

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

if( version_is_less( version: version, test_version: "5.0.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.0.10", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
