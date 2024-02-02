# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vektor-inc:vk_all_in_one_expansion_unit";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127588");
  script_version("2023-11-22T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-11-22 05:05:24 +0000 (Wed, 22 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-10-16 13:10:11 +0000 (Mon, 16 Oct 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-23 18:38:00 +0000 (Thu, 23 Mar 2023)");

  script_cve_id("CVE-2023-0937");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress VK All in One Expansion Unit Plugin < 9.87.1.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/vk-all-in-one-expansion-unit/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'VK All in One Expansion Unit' is prone to
  a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not escape the $_SERVER['REQUEST_URI']
  parameter before outputting it back in an attribute.");

  script_tag(name:"affected", value:"WordPress VK All in One Expansion Unit prior to version
  9.87.1.0.");

  script_tag(name:"solution", value:"Update to version 9.87.1.0 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/5110ff02-c721-43eb-b13e-50aca25e1162/");

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

if( version_is_less( version: version, test_version: "9.87.1.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.87.1.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
