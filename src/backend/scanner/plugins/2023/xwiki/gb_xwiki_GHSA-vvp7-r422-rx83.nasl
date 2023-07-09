# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124307");
  script_version("2023-06-14T05:05:19+0000");
  script_tag(name:"last_modification", value:"2023-06-14 05:05:19 +0000 (Wed, 14 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-04-26 09:03:39 +0000 (Wed, 26 Apr 2023)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2023-29203");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki 13.9-rc-1 < 13.10.8, 14.x < 14.4.3, 14.5.x < 14.7-rc-1 Information Disclosure Vulnerability (GHSA-vvp7-r422-rx83)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It's possible to list some users who are normally not viewable
  from subwiki by requesting users on a subwiki which allows only global users with uorgsuggest.vm.
  This issue only concerns hidden users from main wiki. Note that the disclosed information are the
  username and the first and last name of users, no other information is leaked.");

  script_tag(name:"affected", value:"XWiki version 13.9-rc-1 prior to 13.10.8, 14.x prior to 14.4.3 and 14.5.x prior to
  14.7-rc-1.");

  script_tag(name:"solution", value:"Update to version8 13.10.8, 14.4.3, 14.7-rc-1 or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-vvp7-r422-rx83");

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

if ( version_in_range_exclusive( version:version, test_version_lo:"13.9-rc-1", test_version_up:"13.10.8" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"13.10.8", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"14.0", test_version_up:"14.4.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.4.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range_exclusive( version:version, test_version_lo:"14.5", test_version_up:"14.7-rc-1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.7-rc-1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
