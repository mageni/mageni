# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124374");
  script_version("2023-08-23T05:05:12+0000");
  script_tag(name:"last_modification", value:"2023-08-23 05:05:12 +0000 (Wed, 23 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-07-24 09:27:39 +0000 (Mon, 24 Jul 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2023-29522");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki 7.0-rc-1 < 14.4.8, 14.5 < 14.10.3 Code Injection Vulnerability (GHSA-mjw9-3f9f-jq2w)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to a code injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Any user with view rights can execute arbitrary script macros
  including Groovy and Python macros that allow remote code execution including unrestricted read
  and write access to all wiki contents. The attack works by opening a non-existing page with a
  name crafted to contain a dangerous payload.");

  script_tag(name:"affected", value:"XWiki version 7.0-rc-1 prior to 14.4.8, 14.5 prior to 14.10.3.");

  script_tag(name:"solution", value:"Update to version 14.4.8, 14.10.3 or later.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-mjw9-3f9f-jq2w");

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

if( version_in_range_exclusive( version:version, test_version_lo:"7.0-rc-1", test_version_up:"14.4.8" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.4.8", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"14.5", test_version_up:"14.10.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.10.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
