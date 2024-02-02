# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:axis:axis_os";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.170614");
  script_version("2023-10-24T14:40:27+0000");
  script_tag(name:"last_modification", value:"2023-10-24 14:40:27 +0000 (Tue, 24 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-23 08:36:17 +0000 (Mon, 23 Oct 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-20 18:31:00 +0000 (Fri, 20 Oct 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-21414");

  script_name("AXIS OS Secure Boot Bypass Vulnerability (Oct 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_axis_devices_consolidation.nasl");
  script_mandatory_keys("axis/device/detected");

  script_tag(name:"summary", value:"AXIS OS is prone to a secure boot bypass vulnerability on
  several devices.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The protection for device tampering (commonly known as Secure
  Boot) in AXIS OS was vulnerable to a sophisticated attack to bypass this protection");

  script_tag(name:"affected", value:"- Axis ARTPEC 8 products running AXIS OS 10.11 - 11.5

  - AXIS A8207-VE Mk II < AXIS OS 11.5

  - AXIS Q3527-LVE AXIS OS 10.11 - AXIS OS 11.5");

  script_tag(name:"solution", value:"Update to version 10.12.206, 11.6.94 or later.");

  script_xref(name:"URL", value:"https://www.axis.com/dam/public/45/3c/a1/cve-2023-21414pdf-en-US-412758.pdf");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE, nofork: TRUE ) )
  exit( 0 );

if( ! model = get_kb_item( "axis/device/model" ) )
  exit( 0 );

if( model =~ "^A8207-VE Mk II" ) {

  if( version_is_less( version: version, test_version: "10.12.206" ) ) {
    report = report_fixed_ver( installed_version: version, fixed_version: "10.12.206" );
    security_message( data: report, port: 0 );
    exit( 0 );
  }

  if( version_in_range_exclusive( version: version, test_version_lo: "11.0.0", test_version_up: "11.6.94" ) ) {
    report = report_fixed_ver( installed_version: version, fixed_version: "11.6.94" );
    security_message( data: report, port: 0 );
    exit( 0 );
  }
} else if( model =~ "^ARTPEC 8" || model =~ "^Q3527-LVE" ) {
  if( version_in_range_exclusive( version: version, test_version_lo: "10.11.0", test_version_up: "10.12.206" ) ) {
    report = report_fixed_ver( installed_version: version, fixed_version: "10.12.206" );
    security_message( data: report, port: 0 );
    exit( 0 );
  }

  if( version_in_range_exclusive( version: version, test_version_lo: "11.0.0", test_version_up: "11.6.94" ) ) {
    report = report_fixed_ver( installed_version: version, fixed_version: "11.6.94" );
    security_message( data: report, port: 0 );
    exit( 0 );
  }
}

exit( 99 );