# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpchill:download_monitor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127667");
  script_version("2024-01-01T05:05:52+0000");
  script_tag(name:"last_modification", value:"2024-01-01 05:05:52 +0000 (Mon, 01 Jan 2024)");
  script_tag(name:"creation_date", value:"2023-12-27 12:20:45 +0000 (Wed, 27 Dec 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 13:31:00 +0000 (Thu, 28 Dec 2023)");

  script_cve_id("CVE-2023-34007");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Download Monitor Plugin < 4.8.4 Arbitrary File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/download-monitor/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Download Monitor' is prone to an
  arbitrary file upload vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Authenticated attackers with subscriber-level capabilities or
  above are able to upload arbitrary files on the affected site's server which may make remote code
  execution possible.");

  script_tag(name:"insight", value:"Missing file type validation and access controls on the
  'upload_file' function.");

  script_tag(name:"affected", value:"WordPress Download Monitor prior to version 4.8.4.");

  script_tag(name:"solution", value:"Update to version 4.8.4 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/download-monitor/wordpress-download-monitor-plugin-4-8-3-arbitrary-file-upload-vulnerability");

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

if( version_is_less( version: version, test_version: "4.8.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.8.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
