# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vm2_project:vm2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104844");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-18 08:23:05 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("vm2 End of Life (EOL) Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_javascript_packages_consolidation.nasl");
  script_mandatory_keys("javascript_package/vm2/detected");

  script_tag(name:"summary", value:"vm2 is discontinued and will not receive any security
  updates.");

  script_tag(name:"vuldetect", value:"Checks if the discontinued vm2 product is present on the
  target host.");

  script_tag(name:"impact", value:"A discontinued product is not receiving any security updates from
  the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to compromise the
  security of this host.");

  script_tag(name:"solution", value:"No solution was made available by the vendor.

  Vendor statement: The library contains critical security issues and should not be used for
  production! The maintenance of the project has been discontinued. Consider migrating your code to
  isolated-vm.");

  script_xref(name:"URL", value:"https://github.com/patriksimek/vm2#%EF%B8%8F-project-discontinued-%EF%B8%8F");
  script_xref(name:"URL", value:"https://github.com/patriksimek/vm2/issues/533");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

report = report_fixed_ver( installed_version:version, fixed_version:"None", install_path:location );
security_message( port:port, data:report );
exit( 0 );
