# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bravenewcode:wptouch";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127402");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-04-20 11:08:03 +0000 (Thu, 20 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-13 06:47:00 +0000 (Fri, 13 Jan 2023)");

  script_cve_id("CVE-2022-3416", "CVE-2022-3417");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WPtouch Plugin < 4.3.45 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wptouch/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WPtouch' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-3416: The plugin does not properly validate images to be uploaded, allowing high
  privilege users such as admin to upload arbitrary files on the server even when they should
  not be allowed to.

  - CVE-2022-3417: The plugin unserialises the content of an imported settings file, which could
  lead to PHP object injections issues when an user import (intentionally or not) a malicious
  settings file and a suitable gadget chain is present on the blog.");

  script_tag(name:"affected", value:"WordPress WPtouch plugin prior to version 4.3.45.");

  script_tag(name:"solution", value:"Update to version 4.3.45 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/f927dbe0-3939-4882-a469-1309ac737ee6");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/55772932-eebd-475b-b5df-e80fab288ee5");

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

if( version_is_less( version: version, test_version: "4.3.45" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.3.45", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
