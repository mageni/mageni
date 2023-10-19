# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:freshlightlab:menu_image%2c_icons_made_easy";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126459");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-07-31 12:30:48 +0000 (Mon, 31 Jul 2023)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-04 17:29:00 +0000 (Mon, 04 Apr 2022)");

  script_cve_id("CVE-2022-0450");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Menu Image, Icons Made Easy Plugin < 3.0.6 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/menu-image/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Menu Image, Icons Made Easy' is prone to
  a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not have authorisation and CSRF checks when
  saving menu settings, and does not validate, sanitise and escape them. As a result, any
  authenticate users, such as subscriber can update the settings or arbitrary menu and put
  Cross-Site Scripting payloads in them which will be triggered in the related menu in the
  frontend.");

  script_tag(name:"affected", value:"WordPress Menu Image, Icons Made Easy plugin prior to version 3.0.6.");

  script_tag(name:"solution", value:"Update to version 3.0.6 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/612f9273-acc8-4be6-b372-33f1e687f54a");

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

if( version_is_less( version: version, test_version: "3.0.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.0.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
