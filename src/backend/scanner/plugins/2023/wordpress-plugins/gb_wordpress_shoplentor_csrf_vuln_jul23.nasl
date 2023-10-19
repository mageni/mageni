# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hasthemes:woolentor_-_woocommerce_elementor_addons_%2b_builder";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126435");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-07-18 09:28:06 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-26 01:10:00 +0000 (Wed, 26 Jul 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2022-47172");

  script_name("WordPress ShopLentor Plugin < 2.6.3 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/woolentor-addons/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'ShopLentor' is prone to a cross-site
  request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not have CSRF check in place when updating its
  settings, which could allow attackers to make a logged in admin change them via a CSRF attack");

  script_tag(name:"affected", value:"WordPress ShopLentor plugin prior to version 2.6.3.");

  script_tag(name:"solution", value:"Update to version 2.6.3 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/4387e33d-d6d4-4137-9ee6-c93e91d0f1bb");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.6.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.6.3", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
