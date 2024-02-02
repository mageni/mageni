# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpdeveloper:essential_addons_for_elementor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127652");
  script_version("2023-12-14T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-12-14 05:05:32 +0000 (Thu, 14 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-06 08:00:51 +0000 (Wed, 06 Dec 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-30 04:57:00 +0000 (Thu, 30 Nov 2023)");

  script_cve_id("CVE-2023-32245");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Essential Addons for Elementor Pro Plugin < 5.4.9 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/essential-addons-elementor/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Essential Addons for Elementor Pro' is
  prone to a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Attackers are able to make web requests to arbitrary locations
  originating from the web application which can be used to query and modify information from
  internal services.");

  script_tag(name:"affected", value:"WordPress Essential Addons for Elementor Pro plugin prior to
  version 5.4.9.");

  script_tag(name:"solution", value:"Update to version 5.4.9 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/essential-addons-elementor/wordpress-essential-addons-for-elementor-pro-plugin-5-4-8-unauthenticated-server-side-request-forgery-ssrf-vulnerability");

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

if( version_is_less( version: version, test_version: "5.4.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.4.9", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
