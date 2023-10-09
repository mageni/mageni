# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127532");
  script_version("2023-08-29T05:06:28+0000");
  script_tag(name:"last_modification", value:"2023-08-29 05:06:28 +0000 (Tue, 29 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-25 10:15:22 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2023-40573");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki < 14.10.9, 15.0-rc-1 < 15.4-rc-1 Improper Access Control Vulnerability (GHSA-8xhr-x3v8-rghj)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"XWiki is prone to an improper access control vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"XWiki supports scheduled jobs that contain Groovy scripts.
  Currently, the job checks the content author of the job for programming right. However, modifying
  or adding a job script to a document doesn't modify the content author. Together with a CSRF
  vulnerability in the job scheduler, this can be exploited for remote code execution by an
  attacker with edit right on the wiki.");

  script_tag(name:"affected", value:"XWiki version prior to 14.10.9 and 15.0-rc-1 prior to
  15.4-rc-1.");

  script_tag(name:"solution", value:"Update to version 14.10.9, 15.4-rc-1 or later.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-8xhr-x3v8-rghj");

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

if( version_is_less( version:version, test_version:"14.10.9" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.10.9", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"15.0-rc-1", test_version_up:"15.4-rc-1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.4-rc-1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
