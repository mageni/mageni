# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170575");
  script_version("2023-09-21T05:05:45+0000");
  script_tag(name:"last_modification", value:"2023-09-21 05:05:45 +0000 (Thu, 21 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-20 18:57:58 +0000 (Wed, 20 Sep 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2022-48564");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python < 3.6.13, 3.7.x < 3.7.10, 3.8.x < 3.8.7, 3.9.x < 3.9.1 DoS Vulnerability (bpo-42103) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Python is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"read_ints in plistlib.py is vulnerable to a potential DoS attack
  via CPU and RAM exhaustion when processing malformed Apple Property List files in binary format.");

  script_tag(name:"affected", value:"Python prior to version 3.6.13, versions 3.7.x prior to 3.7.10,
  3.8.x prior to 3.8.7 and 3.9.x prior to 3.9.1.");

  script_tag(name:"solution", value:"Update to version 3.6.13, 3.7.10, 3.8.7, 3.9.1 or later.");

  script_xref(name:"URL", value:"https://mail.python.org/archives/list/security-announce@python.org/thread/K2T3WIJM6OCTVTPW5TVW62EMAULA2426/");
  script_xref(name:"URL", value:"https://bugs.python.org/issue42103");
  script_xref(name:"Advisory-ID", value:"bpo-42103");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+" ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"3.6.13" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.6.13", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.7.0", test_version2:"3.7.9" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.7.10", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.8.0", test_version2:"3.8.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.8.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_is_equal( version:version, test_version:"3.9.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.9.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
