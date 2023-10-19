# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:page_scroll_to_id_project:page_scroll_to_id";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127508");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-03 12:30:03 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-23 15:04:00 +0000 (Mon, 23 Jan 2023)");

  script_cve_id("CVE-2022-4449");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Page scroll to id Plugin < 1.7.6 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/page-scroll-to-id/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Page scroll to id' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not validate and escape some of its shortcode
  attributes before outputting them back in the page.");

  script_tag(name:"affected", value:"WordPress Page scroll to id plugin prior to version 1.7.6.");

  script_tag(name:"solution", value:"Update to version 1.7.6 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/a4895f8d-5a4c-49cb-b144-b761ed82923d");

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

if( version_is_less( version: version, test_version: "1.7.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.7.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
