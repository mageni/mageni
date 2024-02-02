# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124471");
  script_version("2023-11-30T05:06:26+0000");
  script_tag(name:"last_modification", value:"2023-11-30 05:06:26 +0000 (Thu, 30 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-16 12:10:52 +0000 (Thu, 16 Nov 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-14 19:34:00 +0000 (Tue, 14 Nov 2023)");

  script_cve_id("CVE-2023-46731");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki < 14.10.14, 15.0-rc-1 < 15.5.1 RCE Vulnerability (GHSA-62pr-qqf7-hh89)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"XWiki doesn't properly escape the section URL parameter that is
  used in the code for displaying administration sections. This allows any user with read access to
  the document XWiki.AdminSheet (by default, everyone including unauthenticated users) to execute
  code including groovy code.");

  script_tag(name:"affected", value:"XWiki prior to version 14.10.14 and 15.0-rc-1 prior to
  15.5.1.");

  script_tag(name:"solution", value:"Update to version 14.10.14, 15.5.1 or later.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-62pr-qqf7-hh89");

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

if( version_is_less( version: version, test_version: "14.10.14" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "14.10.14", install_path: location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"15.0-rc-1", test_version_up:"15.5.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.5.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
