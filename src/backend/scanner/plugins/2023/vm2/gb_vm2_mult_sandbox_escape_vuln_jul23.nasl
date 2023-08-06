# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vm2_project:vm2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170513");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-14 06:31:05 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2023-37466", "CVE-2023-37903");

  script_name("vm2 <= 3.9.19 Multiple Sandbox Escape Vulnerabilities (Jul 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_javascript_packages_consolidation.nasl");
  script_mandatory_keys("javascript_package/vm2/detected");

  script_tag(name:"summary", value:"vm2 is prone to multiple sandbox escape vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-37466: Promise handler sanitization can be bypassed, allowing attackers to escape
  the sandbox and run arbitrary code.

  - CVE-2023-37903: Node.js custom inspect function allows attackers to escape the sandbox and run
  arbitrary code.");

  script_tag(name:"impact", value:"Exploiting these vulnerabilities leads to remote code execution,
  assuming the attacker has arbitrary code execution primitive inside the context of vm2 sandbox.");

  script_tag(name:"affected", value:"vm2 version 3.9.19 and prior.");

  script_tag(name:"solution", value:"No solution was made available by the vendor.

  Vendor statement: The library contains critical security issues and should not be used for
  production! The maintenance of the project has been discontinued. Consider migrating your code to
  isolated-vm.");

  script_xref(name:"URL", value:"https://github.com/patriksimek/vm2/security/advisories/GHSA-cchq-frgv-rjh5");
  script_xref(name:"URL", value:"https://github.com/patriksimek/vm2/security/advisories/GHSA-g644-9gfx-q4q4");
  script_xref(name:"URL", value:"https://github.com/patriksimek/vm2#%EF%B8%8F-project-discontinued-%EF%B8%8F");
  script_xref(name:"URL", value:"https://github.com/patriksimek/vm2/issues/533");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less_equal( version:version, test_version:"3.9.19" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"None", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
