# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:waspthemes:custom_css_pro";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127639");
  script_version("2023-12-06T05:06:11+0000");
  script_tag(name:"last_modification", value:"2023-12-06 05:06:11 +0000 (Wed, 06 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-11-27 07:20:51 +0000 (Mon, 27 Nov 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-07 18:58:00 +0000 (Fri, 07 Oct 2022)");

  script_cve_id("CVE-2019-5984");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Custom CSS Pro Plugin < 1.0.4 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/custom-css-pro/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Custom CSS Proe' is prone to a cross-site
  request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Attackers are able to hijack the authentication of
  administrators via unspecified vectors.");

  script_tag(name:"affected", value:"WordPress Custom CSS Pro plugin prior to version 1.0.4.");

  script_tag(name:"solution", value:"Update to version 1.0.4 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/custom-css-pro/custom-css-pro-103-cross-site-request-forgery");

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

if( version_is_less( version: version, test_version: "1.0.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.0.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
