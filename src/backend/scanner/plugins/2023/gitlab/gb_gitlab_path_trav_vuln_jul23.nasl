# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127493");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-06 12:40:32 +0000 (Thu, 06 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2023-3484");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 12.8.x < 15.11.11, 16.0.x < 16.0.7, 16.1.x < 16.1.2 Path Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to a path traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker is able to change the name or path of a public
  top-level group in certain situations.");

  script_tag(name:"affected", value:"GitLab versions 12.8.x prior to 15.11.11, 16.0.x prior to
  16.0.7 and 16.1.x prior to 16.1.2.");

  script_tag(name:"solution", value:"Update to version 15.11.11, 16.0.7, 16.1.2 or later.");

  script_xref(name:"URL", value:"https://about.gitlab.com/releases/2023/07/05/security-release-gitlab-16-1-2-released/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version: version, test_version_lo: "12.8.0", test_version_up: "15.11.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "15.11.11", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "16.0.0", test_version_up: "16.0.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "16.0.7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "16.1.0", test_version_up: "16.1.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "16.1.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
