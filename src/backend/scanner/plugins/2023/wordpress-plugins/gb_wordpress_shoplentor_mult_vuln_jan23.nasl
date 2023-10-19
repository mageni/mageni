# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hasthemes:woolentor_-_woocommerce_elementor_addons_%2b_builder";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127100");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-02-28 09:28:06 +0000 (Tue, 28 Feb 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-28 01:52:00 +0000 (Tue, 28 Feb 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-0231", "CVE-2023-0232");

  script_name("WordPress ShopLentor Plugin < 2.5.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/woolentor-addons/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'ShopLentor' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-0231: The plugin does not validate and escape some of its block options before
  outputting them back in a page/post where the block is embed.

  - CVE-2023-0232: The plugin unserializes user input from cookies in order to track viewed
  products and user data.");

  script_tag(name:"affected", value:"WordPress ShopLentor plugin prior to version 2.5.4.");

  script_tag(name:"solution", value:"Update to version 2.5.4 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/533c19d5-219c-4389-a8bf-8b3a35b33b20");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/1885a708-0e8a-4f4c-8e26-069bebe9a518");

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

if( version_is_less( version: version, test_version: "2.5.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.5.4", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
