# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:atlas_gondal:export_all_urls";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126481");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-09-13 11:20:45 +0000 (Wed, 13 Sep 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-18 11:50:00 +0000 (Tue, 18 Jul 2023)");

  script_cve_id("CVE-2023-3118");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Export All URLs Plugin < 4.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/export-all-urls/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Export All URLs' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not sanitise and escape a parameter before
  outputting them back in the page, leading to a Reflected Cross-Site Scripting which could be
  used against high privilege users such as admin.");

  script_tag(name:"affected", value:"WordPress Export All URLs prior to version 4.6.");

  script_tag(name:"solution", value:"Update to version 4.6 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/8a9efc8d-561a-42c6-8e61-ae5c3be581ea");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "4.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
