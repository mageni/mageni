# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mybb:mybb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127617");
  script_version("2023-11-16T05:05:14+0000");
  script_tag(name:"last_modification", value:"2023-11-16 05:05:14 +0000 (Thu, 16 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-10 10:45:46 +0000 (Fri, 10 Nov 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-14 17:07:00 +0000 (Tue, 14 Nov 2023)");

  script_cve_id("CVE-2023-45556", "CVE-2023-46251");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MyBB < 1.8.37 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_detect.nasl");
  script_mandatory_keys("MyBB/installed");

  script_tag(name:"summary", value:"MyBB is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-45556: Themes Admin CP module allows remote authenticated users to inject HTML,
  triggered in Admin CP.

  - CVE-2023-46251: Custom MyCode (BBCode) for the visual editor (SCEditor) doesn't escape input
  properly when rendering HTML, resulting in a DOM-based XSS vulnerability.");

  script_tag(name:"affected", value:"MyBB prior to version 1.8.37.");

  script_tag(name:"solution", value:"Update to version 1.8.37 or later.");

  script_xref(name:"URL", value:"https://github.com/mybb/mybb/security/advisories/GHSA-4xqm-3cm2-5xgf");
  script_xref(name:"URL", value:"https://github.com/mybb/mybb/security/advisories/GHSA-wj33-q7vj-9fr8");

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

if( version_is_less( version: version, test_version: "1.8.37" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.8.37", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
