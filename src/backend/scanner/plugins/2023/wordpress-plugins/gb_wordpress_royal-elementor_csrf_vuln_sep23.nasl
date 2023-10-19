# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:royal-elementor-addons:royal_elementor_addons";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126509");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-11 10:50:31 +0200 (Wed, 11 Oct 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-10 14:54:00 +0000 (Tue, 10 Oct 2023)");

  script_cve_id("CVE-2022-47175");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress The Royal Elementor Addons Plugin < 1.3.76 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/royal-elementor-addons/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'The Royal Elementor Addons' is prone to
  a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Cross-site request forgery due to missing or incorrect nonce
  validation on several functions including wpr_rating_dismiss_notice, wpr_rating_already_rated,
  wpr_pro_features_dismiss_notice.");

  script_tag(name:"affected", value:"WordPress The Royal Elementor Addons plugin prior to version
  1.3.76.");

  script_tag(name:"solution", value:"Update to version 1.3.76 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/royal-elementor-addons/royal-elementor-addons-1375-cross-site-request-forgery");

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

if( version_is_less( version: version, test_version: "1.3.76" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.3.76", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
