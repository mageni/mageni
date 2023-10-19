# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:brizy:unyson";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126484");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-18 11:45:48 +0000 (Fri, 18 Aug 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-29 16:09:00 +0000 (Fri, 29 Jul 2022)");

  script_cve_id("CVE-2022-2219");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Unyson Plugin < 2.7.27 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/unyson/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Unyson' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not sanitise and escape a parameter before
  outputting it back in the page, leading to a Reflected Cross-Site Scripting.");

  script_tag(name:"affected", value:"WordPress Unyson plugin prior to version 2.7.27.");

  script_tag(name:"solution", value:"Update to version 2.7.27 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/1240797c-7f45-4c36-83f0-501c544ce76a");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.7.27" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.7.27", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
