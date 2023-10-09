# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mybb:mybb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124418");
  script_version("2023-08-31T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-08-31 05:05:25 +0000 (Thu, 31 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-30 09:45:46 +0000 (Wed, 30 Aug 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2023-41362");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MyBB < 1.8.36 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_detect.nasl");
  script_mandatory_keys("MyBB/installed");

  script_tag(name:"summary", value:"MyBB is prone to a Remote Code Execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Improper validation logic in the Admin CP's Templates module
  allows remote authenticated users to execute arbitrary code (RCE) by supplying specially crafted
  template content.");

  script_tag(name:"affected", value:"MyBB prior to version 1.8.36.");

  script_tag(name:"solution", value:"Update to version 1.8.36 or later.");

  script_xref(name:"URL", value:"https://github.com/mybb/mybb/security/advisories/GHSA-pr74-wvp3-q6f5");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit(0);

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.8.36" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.8.36", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
