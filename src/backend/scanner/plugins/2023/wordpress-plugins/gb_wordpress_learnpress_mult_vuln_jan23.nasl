# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:thimpress:learnpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127312");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-01-26 09:00:32 +0000 (Thu, 26 Jan 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-02 15:12:00 +0000 (Thu, 02 Feb 2023)");

  script_cve_id("CVE-2022-45808", "CVE-2022-45820", "CVE-2022-47615");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress LearnPress Plugin <= 4.1.7.3.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/learnpress/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'LearnPress' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-45808: Unauthenticated local file inclusion (LFI)

  - CVE-2022-45820: Authenticated SQL injection (SQLi)

  - CVE-2022-47615: Unauthenticated SQL injection (SQLi)");

  script_tag(name:"affected", value:"WordPress LearnPress plugin version 4.1.7.3.2 and prior.");

  script_tag(name:"solution", value:"Update to version 4.2 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/learnpress/wordpress-learnpress-wordpress-lms-plugin-plugin-4-1-7-3-2-sql-injection");
  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/learnpress/wordpress-learnpress-plugin-4-1-7-3-2-auth-sql-injection-sqli-vulnerability");
  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/learnpress/wordpress-learnpress-plugin-4-1-7-3-2-local-file-inclusion");
  script_xref(name:"URL", value:"https://patchstack.com/articles/multiple-critical-vulnerabilities-fixed-in-learnpress-plugin-version/");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos[ "version" ];
location = infos[ "location" ];

if( version_is_less_equal( version: version, test_version: "4.1.7.3.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
