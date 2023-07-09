# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124324");
  script_version("2023-06-14T05:05:19+0000");
  script_tag(name:"last_modification", value:"2023-06-14 05:05:19 +0000 (Wed, 14 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-05-19 08:03:39 +0000 (Fri, 19 May 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2023-29208");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki 1.2-milestone-1 < 13.10.11, 14.x < 14.4.7, 14.5.x < 14.10 Information Disclosure Vulnerability (GHSA-4f8g-fq6x-jqrr)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Rights added to a document are not taken into account for
  viewing it once it's deleted. Note that this vulnerability only impact deleted documents that
  were containing view rights: the view rights provided on a space of a deleted document are
  properly checked.");

  script_tag(name:"affected", value:"XWiki version 1.2-milestone-1 prior to 13.10.11, 14.x prior
  to 14.4.7 and 14.5.x prior to 14.10.");

  script_tag(name:"solution", value:"Update to version 13.10.11, 14.4.7, 14.10 or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-4f8g-fq6x-jqrr");

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

if( version_in_range_exclusive( version:version, test_version_lo:"1.2-milestone-1", test_version_up:"13.10.11" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"13.10.11", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"14.0", test_version_up:"14.4.7" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.4.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range_exclusive( version:version, test_version_lo:"14.5", test_version_up:"14.10" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.10", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
