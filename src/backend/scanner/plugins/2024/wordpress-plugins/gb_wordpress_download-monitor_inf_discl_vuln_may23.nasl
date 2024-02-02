# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpchill:download_monitor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127679");
  script_version("2024-01-12T16:12:12+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:12 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-09 07:10:45 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-11 19:57:00 +0000 (Thu, 11 Jan 2024)");

  script_cve_id("CVE-2022-45354");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Download Monitor Plugin < 4.7.70 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/download-monitor/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Download Monitor' is prone to an
  information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unauthenticated attackers could extract sensitive data
  including user reports, download reports, and user data including email, role, id and other info
  (not passwords) via REST API.");

  script_tag(name:"affected", value:"WordPress Download Monitor prior to version 4.7.70.");

  script_tag(name:"solution", value:"Update to version 4.7.70 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/download-monitor/wordpress-download-monitor-plugin-4-7-60-sensitive-data-exposure-vulnerability");

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

if( version_is_less( version: version, test_version: "4.7.70" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.7.70", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
