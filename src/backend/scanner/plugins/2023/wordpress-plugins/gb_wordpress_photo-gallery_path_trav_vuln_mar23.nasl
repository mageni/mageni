# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:10web:photo_gallery";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127398");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-04-18 10:08:03 +0000 (Tue, 18 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-25 19:31:00 +0000 (Tue, 25 Apr 2023)");

  script_cve_id("CVE-2023-1427");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Photo Gallery Plugin < 1.8.15 Path Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/photo-gallery/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Photo Gallery' is prone to a
  path traversal vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin did not ensure that uploaded files are kept inside
  its uploads folder, allowing high privilege users to put images anywhere in the filesystem via a
  path traversal vector.");

  script_tag(name:"affected", value:"WordPress Photo Gallery plugin prior to version 1.8.15.");

  script_tag(name:"solution", value:"Update to version 1.8.15 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/c8917ba2-4cb3-4b09-8a49-b7c612254946");

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

if( version_is_less( version: version, test_version: "1.8.15" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.8.15", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
