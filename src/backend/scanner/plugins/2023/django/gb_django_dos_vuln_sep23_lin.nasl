# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:djangoproject:django";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127609");
  script_version("2023-11-16T05:05:14+0000");
  script_tag(name:"last_modification", value:"2023-11-16 05:05:14 +0000 (Thu, 16 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-06 10:20:40 +0000 (Mon, 06 Nov 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-13 15:32:00 +0000 (Mon, 13 Nov 2023)");

  script_cve_id("CVE-2023-41164");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django < 3.2.21, 4.1.x < 4.1.11, 4.2.x < 4.2.5 DoS Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_django_detect_lin.nasl");
  script_mandatory_keys("Django/Linux/Ver");

  script_tag(name:"summary", value:"Django is prone to a denial of service (DoS) vulnerability in
  django.utils.encoding.uri_to_iri().");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"django.utils.encoding.uri_to_iri() was subject to potential
  denial of service attack via certain inputs with a very large number of Unicode characters.");

  script_tag(name:"affected", value:"Django prior to version 3.2.21, version 4.1.x prior to
  4.1.11 and 4.2.x through 4.2.5.");

  script_tag(name:"solution", value:"Update to version 3.2.21, 4.1.11, 4.2.5 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2023/sep/04/security-releases/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.2.21" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2.21", install_path: location );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.1.0", test_version_up: "4.1.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.1.11", install_path: location );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.2.0", test_version_up: "4.2.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.2.5", install_path: location );
  security_message( port: 0, data: report );
  exit( 0 );
}

exit( 99 );
