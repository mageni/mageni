# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:opencart:opencart";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126421");
  script_version("2023-07-07T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-07-07 05:05:26 +0000 (Fri, 07 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-06-26 22:10:42 +0000 (Mon, 26 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2013-1891");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenCart 1.4.7 < 2.0.0.0 Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("opencart_detect.nasl");
  script_mandatory_keys("OpenCart/installed");

  script_tag(name:"summary", value:"OpenCart is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Insufficient sanitization of user-supplied data.");

  script_tag(name:"affected", value:"OpenCart versions 1.4.7 prior to 2.0.0.0.");

  script_tag(name:"solution", value:"Update to version 2.0.0.0 or later.");

  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2013/Mar/176");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version: version, test_version_lo: "1.4.7", test_version_up: "2.0.0.0" ) ) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.0.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
