# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:clogica:all_404_redirect_to_homepage";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127406");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-04-25 07:08:03 +0000 (Tue, 25 Apr 2023)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-24 15:41:00 +0000 (Mon, 24 May 2021)");

  script_cve_id("CVE-2021-24326");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress All 404 Redirect to Homepage Plugin < 1.21 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/all-404-redirect-to-homepage/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'All 404 Redirect to Homepage' is prone
  to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The tab parameter of the settings page of the plugin is
  vulnerable to an authenticated reflected cross-site scripting (XSS).");

  script_tag(name:"affected", value:"WordPress All 404 Redirect to Homepage plugin prior to
  version 1.21.");

  script_tag(name:"solution", value:"Update to version 1.21 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/63d6ca03-e0df-40db-9839-531c13619094");

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

if( version_is_less( version: version, test_version: "1.21" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.21", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
