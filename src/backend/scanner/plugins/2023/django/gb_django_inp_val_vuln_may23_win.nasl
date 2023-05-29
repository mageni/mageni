# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:djangoproject:django";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126363");
  script_version("2023-05-12T09:09:03+0000");
  script_tag(name:"last_modification", value:"2023-05-12 09:09:03 +0000 (Fri, 12 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-09 11:32:07 +0000 (Tue, 09 May 2023)");
  script_tag(name:"cvss_base", value:"5.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2023-31047");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django 3.2.x < 3.2.19, 4.1.x < 4.1.9, 4.2.x < 4.2.1 Input Validation Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_django_detect_win.nasl");
  script_mandatory_keys("django/windows/detected");

  script_tag(name:"summary", value:"Django is prone to an input validation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Uploading multiple files using one form field has never been
  supported by forms.FileField or forms.ImageField as only the last uploaded file was validated.");

  script_tag(name:"affected", value:"Django versions 3.2.x prior to 3.2.19, 4.1.x prior to 4.1.9,
  4.2.x prior to 4.2.1.");

  script_tag(name:"solution", value:"Update to version 3.2.19, 4.1.9, 4.2.1 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2023/may/03/security-releases/");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) )
  exit( 0 );

version = infos[ "version" ];
location = infos[ "location" ];

if( version_in_range_exclusive( version: version, test_version_lo: "3.2.0", test_version_up: "3.2.19" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2.19", install_path: location );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.1.0", test_version_up: "4.1.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.1.9", install_path: location );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.2.0", test_version_up: "4.2.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.2.1", install_path: location );
  security_message( port: 0, data: report );
  exit( 0 );
}

exit( 99 );

