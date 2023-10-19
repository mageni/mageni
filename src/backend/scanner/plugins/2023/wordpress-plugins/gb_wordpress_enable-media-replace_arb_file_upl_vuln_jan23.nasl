# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:shortpixel:enable_media_replace";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127506");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-01 08:40:03 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-15 16:04:00 +0000 (Wed, 15 Feb 2023)");

  script_cve_id("CVE-2023-0255");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Enable Media Replace Plugin < 4.0.2 Arbitrary File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/enable-media-replace/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Enable Media Replace' is prone to an
  arbitrary file upload vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not prevent authors from uploading arbitrary
  files to the site, which may allow them to upload PHP shells on affected sites.");

  script_tag(name:"affected", value:"WordPress Enable Media Replace plugin prior to version
  4.0.2.");

  script_tag(name:"solution", value:"Update to version 4.0.2 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/b0239208-1e23-4774-9b8c-9611704a07a0");

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

if( version_is_less( version: version, test_version: "4.0.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.0.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
