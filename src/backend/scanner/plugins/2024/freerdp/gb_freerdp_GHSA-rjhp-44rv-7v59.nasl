# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:freerdp_project:freerdp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114298");
  script_version("2024-01-29T05:05:18+0000");
  script_tag(name:"last_modification", value:"2024-01-29 05:05:18 +0000 (Mon, 29 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-22 17:00:11 +0000 (Mon, 22 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-26 20:24:00 +0000 (Fri, 26 Jan 2024)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2024-22211");

  script_name("FreeRDP Heap Buffer Overflow Vulnerability (GHSA-rjhp-44rv-7v59)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_freerdp_detect_lin.nasl");
  script_mandatory_keys("FreeRDP/Linux/Ver");

  script_tag(name:"summary", value:"FreeRDP is prone to a heap buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow in freerdp_bitmap_planar_context_reset leads
  to a heap buffer overflow.");

  script_tag(name:"affected", value:"FreeRDP versions through 2.11.4 and 3.x through 3.1.0.");

  script_tag(name:"solution", value:"Update to version 2.11.5, 3.2.0 or later.");

  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-rjhp-44rv-7v59");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"2.11.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version:"2.11.5", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"3.0", test_version_up:"3.2.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.2.0", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
