# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:djangoproject:django";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127611");
  script_version("2024-01-10T05:05:17+0000");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2023-11-07 08:50:40 +0000 (Tue, 07 Nov 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-09 17:58:00 +0000 (Thu, 09 Nov 2023)");

  script_cve_id("CVE-2023-46695");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django < 3.2.23, 4.1.x < 4.1.13, 4.2.x < 4.2.7 DoS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_django_detect_win.nasl");
  script_mandatory_keys("django/windows/detected");

  script_tag(name:"summary", value:"Django is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The NFKC normalization is slow on Windows. As a consequence,
  django.contrib.auth.forms.UsernameField was subject to a potential denial of service attack via
  certain inputs with a very large number of Unicode characters.");

  script_tag(name:"affected", value:"Django versions prior to 3.2.23, 4.1.x prior to 4.1.13 and
  4.2.x prior to 4.2.7.");

  script_tag(name:"solution", value:"Update to version 3.2.23, 4.1.13, 4.2.7 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2023/nov/01/security-releases/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.2.23" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2.23", install_path: location );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.1.0", test_version_up: "4.1.13" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.1.13", install_path: location );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.2.0", test_version_up: "4.2.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.2.7", install_path: location );
  security_message( port: 0, data: report );
  exit( 0 );
}

exit( 99 );
