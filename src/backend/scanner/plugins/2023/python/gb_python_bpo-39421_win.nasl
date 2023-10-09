# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170577");
  script_version("2023-09-21T05:05:45+0000");
  script_tag(name:"last_modification", value:"2023-09-21 05:05:45 +0000 (Thu, 21 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-20 18:57:58 +0000 (Wed, 20 Sep 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2022-48560");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python < 3.6.11, 3.7.x < 3.7.7, 3.8.x < 3.8.2 Use After Free Vulnerability (bpo-39421) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Python is prone to an use after free vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A use-after-free exists in Python via heappushpop in heapq.");

  script_tag(name:"affected", value:"Python prior to version 3.6.11, versions 3.7.x prior to 3.7.7,
  3.8.x prior to 3.8.2 and 3.9.x prior to 3.9.0.");

  script_tag(name:"solution", value:"Update to version 3.6.11, 3.7.7, 3.8.2, 3.9.0 or later.");

  script_xref(name:"URL", value:"https://mail.python.org/archives/list/security-announce@python.org/thread/TRTM4UVSANUWNHC2QY2X73E5IBQLQU76/");
  script_xref(name:"URL", value:"https://bugs.python.org/issue39421");
  script_xref(name:"Advisory-ID", value:"bpo-39421");

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

if( version_is_less( version:version, test_version:"3.6.11" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.6.11", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.7.0", test_version2:"3.7.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.7.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.8.0", test_version2:"3.8.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.8.2", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"3.9.0a1", test_version_up:"3.9.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.9.0", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
