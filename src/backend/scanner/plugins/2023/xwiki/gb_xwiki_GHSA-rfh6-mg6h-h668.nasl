# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124309");
  script_version("2023-06-14T05:05:19+0000");
  script_tag(name:"last_modification", value:"2023-06-14 05:05:19 +0000 (Wed, 14 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-04-26 09:03:39 +0000 (Wed, 26 Apr 2023)");
  script_tag(name:"cvss_base", value:"8.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:P");

  script_cve_id("CVE-2023-29511");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki 1.5-m2 < 13.10.11, 14.x < 14.4.8, 14.5.x < 14.10.1 15.x < 15.0-rc-1 Privilege Escalation Vulnerability (GHSA-rfh6-mg6h-h668)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Any user with edit rights on a page (e.g., it's own user page),
  can execute arbitrary Groovy, Python or Velocity code in XWiki leading to full access to the
  XWiki installation. The root cause is improper escaping of the section ids in
  XWiki.AdminFieldsDisplaySheet. This page is installed by default.");

  script_tag(name:"affected", value:"XWiki version 1.5-m2 prior to 13.10.11, 14.x prior to
  14.4.8, 14.5.x prior to 14.10.1 and 15.x prior to 15.0-rc-1.");

  script_tag(name:"solution", value:"Update to version 13.10.11, 14.4.8, 14.10.1, 15.0-rc-1 or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-rfh6-mg6h-h668");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version:version, test_version_lo:"1.5-m2", test_version_up:"13.10.11" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"13.10.11", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"14.0", test_version_up:"14.4.8" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.4.8", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"14.5", test_version_up:"14.10.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.10.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range_exclusive( version:version, test_version_lo:"15.0", test_version_up:"15.0-rc-1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.0-rc-1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
