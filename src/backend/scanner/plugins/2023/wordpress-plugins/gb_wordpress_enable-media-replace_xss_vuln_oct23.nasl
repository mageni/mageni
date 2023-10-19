# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:shortpixel:enable_media_replace";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126520");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-17 09:40:03 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2023-4643");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Enable Media Replace Plugin < 4.1.3 PHP Object Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/enable-media-replace/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Enable Media Replace' is prone to an PHP
  object injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin unserializes user input via the Remove Background
  feature, which could allow Author+ users to perform PHP Object Injection when a suitable gadget
  is present on the blog.");

  script_tag(name:"affected", value:"WordPress Enable Media Replace plugin prior to version
  4.1.3.");

  script_tag(name:"solution", value:"Update to version 4.1.3 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/d9125604-2236-435c-a67c-07951a1fc5b1/");

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

if( version_is_less( version: version, test_version: "4.1.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.1.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
