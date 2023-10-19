# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:duplicate_page_and_post_project:duplicate_page_and_post";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127560");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-09-20 12:40:45 +0000 (Wed, 20 Sep 2023)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 17:43:00 +0000 (Tue, 16 Aug 2022)");

  script_cve_id("CVE-2022-2152");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Duplicate Page and Post Plugin < 2.8 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/duplicate-wp-page-post/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Duplicate Page and Post' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not sanitise and escape its settings, allowing
  high privilege users such as admin to perform cross-site scripting (XSS) attacks even when the
  unfiltered_html capability is disallowed.");

  script_tag(name:"affected", value:"WordPress Duplicate Page and Post prior to version 2.8.");

  script_tag(name:"solution", value:"Update to version 2.8 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/e972e2c5-0d56-4d2a-81cc-2b0dff750124");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.8", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
