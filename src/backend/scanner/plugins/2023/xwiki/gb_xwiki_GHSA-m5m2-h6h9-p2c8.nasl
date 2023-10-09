# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124431");
  script_version("2023-09-12T05:05:19+0000");
  script_tag(name:"last_modification", value:"2023-09-12 05:05:19 +0000 (Tue, 12 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-06 19:30:39 +0000 (Wed, 06 Sep 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2023-41046");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki 7.2 < 14.10.10, 15.0-rc-1 < 15.4-rc-1 Code Injection Vulnerability (GHSA-m5m2-h6h9-p2c8)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"XWiki is prone to a code injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"XWiki allows to execute Velocity code without having script
  right by creating an XClass with a property of type 'TextArea' and content type 'VelocityCode' or
  'VelocityWiki'.");

  script_tag(name:"affected", value:"XWiki versions 7.2 prior to 14.10.10 and 15.0-rc-1 prior to
  15.4-rc-1.");

  script_tag(name:"solution", value:"Update to version 14.10.10, 15.4-rc-1 or later.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-m5m2-h6h9-p2c8");

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

if( version_in_range_exclusive( version:version, test_version_lo:"7.2", test_version_up:"14.10.10" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.10.10", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"15.0-rc-1", test_version_up:"15.4-rc-1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.4-rc-1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
