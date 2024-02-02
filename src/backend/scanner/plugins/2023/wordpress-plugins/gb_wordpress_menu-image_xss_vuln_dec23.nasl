# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:freshlightlab:menu_image%2c_icons_made_easy";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126624");
  script_version("2024-01-01T05:05:52+0000");
  script_tag(name:"last_modification", value:"2024-01-01 05:05:52 +0000 (Mon, 01 Jan 2024)");
  script_tag(name:"creation_date", value:"2023-12-28 10:39:48 +0000 (Thu, 28 Dec 2023)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-27 21:25:00 +0000 (Wed, 27 Dec 2023)");

  script_cve_id("CVE-2023-50826");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("WordPress Menu Image, Icons Made Easy Plugin <= 3.10 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/menu-image/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Menu Image, Icons Made Easy' is prone to
  a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Attacker could inject malicious scripts, such as redirects,
  advertisements, and other HTML payloads into your website which will be executed when guests
  visit your site.");

  script_tag(name:"affected", value:"WordPress Menu Image, Icons Made Easy plugin version 3.10 and
  prior.");

  script_tag(name:"solution", value:"No known solution is available as of 28th December, 2023.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/menu-image/wordpress-menu-image-icons-made-easy-plugin-3-10-cross-site-scripting-xss-vulnerability");

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

if ( version_is_less_equal( version: version, test_version: "3.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
