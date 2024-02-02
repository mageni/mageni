# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nested_pages_project:nested_pages";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124492");
  script_version("2023-12-29T16:09:56+0000");
  script_tag(name:"last_modification", value:"2023-12-29 16:09:56 +0000 (Fri, 29 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-20 10:32:43 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-18 19:48:00 +0000 (Mon, 18 Dec 2023)");

  script_cve_id("CVE-2023-49195");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("WordPress Nested Pages Plugin <= 3.2.6 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-nested-pages/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Nested Pages' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This could allow a malicious actor to inject malicious scripts,
  such as redirects, advertisements, and other HTML payloads into your website which will be
  executed when guests visit your site.");

  script_tag(name:"affected", value:"WordPress Nested Pages plugin version 3.2.6 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 20th December, 2023.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/wp-nested-pages/wordpress-nested-pages-plugin-3-2-6-cross-site-scripting-xss-vulnerability");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less_equal( version: version, test_version: "3.2.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 0 );
