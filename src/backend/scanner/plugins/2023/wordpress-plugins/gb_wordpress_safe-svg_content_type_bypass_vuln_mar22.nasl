# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:safe_svg_project:safe_svg";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126485");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-09-18 12:00:12 +0000 (Mon, 18 Sep 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-27 12:35:00 +0000 (Wed, 27 Apr 2022)");

  script_cve_id("CVE-2022-1091");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Safe SVG Plugin < 1.9.10 Contet-Type Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/safe-svg/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Safe SVG' is prone to a
  content-type bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Plugin could be bypassed by spoofing the content-type in the
  POST request to upload a file.");

  script_tag(name:"affected", value:"WordPress Safe SVG plugin prior to version 1.9.10.");

  script_tag(name:"solution", value:"Update to version 1.9.10 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/safe-svg/safe-svg-199-content-type-bypass");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.9.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.9.10", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
