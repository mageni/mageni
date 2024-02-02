# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cyr_to_lat_project:cyr_to_lat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127607");
  script_version("2023-11-03T16:10:08+0000");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-10-30 12:08:08 +0000 (Mon, 30 Oct 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-27 18:47:00 +0000 (Fri, 27 Oct 2023)");

  script_cve_id("CVE-2022-4290");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Cyr to Lat enhanced Plugin < 3.7 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/cyr3lat/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Cyr to Lat enhanced' is prone to an SQL
  injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Insufficient escaping on the user supplied parameter in
  'ctl_sanitize_title' function and lack of sufficient preparation on the existing SQL query.");

  script_tag(name:"affected", value:"WordPress Cyr to Lat enhanced plugin prior to version 3.7.");

  script_tag(name:"solution", value:"Update to version 3.7 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/c9c29130-1b42-4edd-ad62-6f635e03ae31");

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

if( version_is_less( version: version, test_version: "3.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
