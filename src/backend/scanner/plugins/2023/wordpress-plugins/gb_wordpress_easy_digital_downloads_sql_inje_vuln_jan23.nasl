# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sandhillsdev:easy_digital_downloads";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126508");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-09-05 07:03:12 +0000 (Tue, 05 Sep 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-26 18:46:00 +0000 (Thu, 26 Jan 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-23489");

  script_name("WordPress Easy Digital Downloads Plugin 3.1.0.2 - 3.1.0.3 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/easy-digital-downloads/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Easy Digital Downloads' is prone to an
  SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not properly sanitise and escape the s parameter
  before using it in a SQL statement via the edd_download_search AJAX action, leading to an SQL
  injection exploitable by unauthenticated users.");

  script_tag(name:"affected", value:"WordPress Easy Digital Downloads plugin version 3.1.0.2 and
  3.1.0.3.");

  script_tag(name:"solution", value:"Update to version 3.1.0.4 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/c5a6830c-6420-42fc-b20c-8e20224d6f18");

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

if( version_in_range_exclusive( version: version, test_version_lo: "3.1.0.2", test_version_up: "3.1.0.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.0.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
