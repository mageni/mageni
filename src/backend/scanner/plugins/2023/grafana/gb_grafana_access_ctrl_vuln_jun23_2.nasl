# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:grafana:grafana";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124342");
  script_version("2023-06-30T05:06:12+0000");
  script_tag(name:"last_modification", value:"2023-06-30 05:06:12 +0000 (Fri, 30 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-23 07:21:18 +0000 (Fri, 23 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:P");

  script_cve_id("CVE-2023-3128");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana 6.7.x < 8.5.27, 9.x < 9.2.20, 9.3.x < 9.3.16, 9.4.x < 9.4.13, 9.5.x < 9.5.5, 10.x < 10.0.1 Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Grafana validates Azure Active Directory accounts based on the
  email claim. On Azure AD, the profile email field is not unique across Azure AD tenants. This
  can enable a Grafana account takeover and authentication bypass when Azure AD OAuth is configured
  with a multi-tenant Azure AD OAuth application.");

  script_tag(name:"affected", value:"Grafana versions 6.7.x prior to 8.5.27, version 9.x prior to 9.2.20,
  9.3.x prior to 9.3.16, 9.4.x prior to 9.4.13, 9.5.x prior to 9.5.5 and 10.x prior to 10.0.1.");

  script_tag(name:"solution", value:"Update to version 8.5.27, 9.2.20, 9.3.16, 9.4.13, 9.5.5,
  10.0.1 or later.");

  script_xref(name:"URL", value:"https://grafana.com/blog/2023/06/22/grafana-security-release-for-cve-2023-3128/");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_in_range_exclusive( version: version, test_version_lo: "6.7.0", test_version_up: "8.5.27" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.5.27", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if ( version_in_range_exclusive( version: version, test_version_lo: "9.0.0", test_version_up: "9.2.20" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.2.20", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if ( version_in_range_exclusive( version: version, test_version_lo: "9.3.0", test_version_up: "9.3.16" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.3.16", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if ( version_in_range_exclusive( version: version, test_version_lo: "9.4.0", test_version_up: "9.4.13" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.4.13", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if ( version_in_range_exclusive( version: version, test_version_lo: "9.5.0", test_version_up: "9.5.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.5.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if ( version_in_range_exclusive( version: version, test_version_lo: "10.0", test_version_up: "10.0.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.0.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
