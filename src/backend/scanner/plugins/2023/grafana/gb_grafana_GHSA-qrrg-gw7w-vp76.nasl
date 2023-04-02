# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:grafana:grafana";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127372");
  script_version("2023-03-27T10:09:49+0000");
  script_tag(name:"last_modification", value:"2023-03-27 10:09:49 +0000 (Mon, 27 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-23 12:00:18 +0000 (Thu, 23 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:M/C:C/I:C/A:N");

  script_cve_id("CVE-2023-1410");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana < 8.5.22, 9.2.x < 9.2.15, 9.3.x < 9.3.11, 9.4.x < 9.4.7 XSS Vulnerability (GHSA-qrrg-gw7w-vp76)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The stored cross-site scripting (XSS) is possible due to
  improper sanitization of the Function Description value.");

  script_tag(name:"affected", value:"Grafana prior to version 8.5.22, 9.2.x prior to 9.2.15,
  9.3.x prior to 9.3.11 and 9.4.x prior to 9.4.7.");

  script_tag(name:"solution", value:"Update to version 8.5.22, 9.2.15, 9.3.11, 9.4.7 or later.");

  script_xref(name:"URL", value:"https://github.com/grafana/bugbounty/security/advisories/GHSA-qrrg-gw7w-vp76");
  script_xref(name:"URL", value:"https://grafana.com/blog/2023/03/22/grafana-security-release-new-versions-with-security-fixes-for-cve-2023-1410/");


  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "8.5.22" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.5.22", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.2.0", test_version_up: "9.2.15" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.2.15", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.3.0", test_version_up: "9.3.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.3.11", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.4.0", test_version_up: "9.4.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.4.7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
