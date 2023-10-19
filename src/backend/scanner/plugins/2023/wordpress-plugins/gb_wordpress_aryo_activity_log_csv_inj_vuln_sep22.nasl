# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:activity_log_project:activity_log";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126445");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-07-27 08:30:48 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-09 14:04:00 +0000 (Wed, 09 Nov 2022)");

  script_cve_id("CVE-2022-27858");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Aryo Activity Log Plugin < 2.8.4 CSV Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/aryo-activity-log/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Aryo Activity Log' is prone to a CSV
  injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not validate data when output it back in a CSV
  file, which could lead to CSV injection");

  script_tag(name:"affected", value:"WordPress Aryo Activity Log plugin prior to version 2.8.4.");

  script_tag(name:"solution", value:"Update to version 2.8.4 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/d43c4ff8-fec5-4202-b534-afdded91ed65");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.8.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.8.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
