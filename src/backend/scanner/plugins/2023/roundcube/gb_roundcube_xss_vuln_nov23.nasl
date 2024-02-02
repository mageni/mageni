# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:roundcube:webmail";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126526");
  script_version("2023-11-16T05:05:14+0000");
  script_tag(name:"last_modification", value:"2023-11-16 05:05:14 +0000 (Thu, 16 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-10-19 08:02:08 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-15 05:15:00 +0000 (Wed, 15 Nov 2023)");

  script_cve_id("CVE-2023-47272");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Roundcube Webmail < 1.5.6, 1.6.x < 1.6.5 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_roundcube_http_detect.nasl");
  script_mandatory_keys("roundcube/detected");

  script_tag(name:"summary", value:"Roundcube Webmail is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw allows XSS in setting Content-Type/Content-Disposition
  for attachment preview/download.");

  script_tag(name:"affected", value:"Roundcube Webmail versions prior to 1.5.6 and 1.6.x
  prior to 1.6.5.");

  script_tag(name:"solution", value:"Update to version 1.5.6, 1.6.5 or later.

  Note: The vendor doesn't plan any more releases in the 1.4 line.");

  script_xref(name:"URL", value:"https://roundcube.net/news/2023/11/05/security-updates-1.6.5-and-1.5.6");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less( version: version, test_version: "1.5.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.5.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if ( version_in_range_exclusive( version: version, test_version_lo: "1.6", test_version_up: "1.6.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.6.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
