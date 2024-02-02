# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpclever:wpc_smart_wishlist_for_woocommerce";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127618");
  script_version("2023-11-16T05:05:14+0000");
  script_tag(name:"last_modification", value:"2023-11-16 05:05:14 +0000 (Thu, 16 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-14 08:30:07 +0000 (Tue, 14 Nov 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-15 02:26:00 +0000 (Wed, 15 Nov 2023)");

  script_cve_id("CVE-2023-34386");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WPC Smart Wishlist for WooCommerce Plugin < 4.7.2 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/woo-smart-wishlist/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WPC Smart Wishlist for WooCommerce' is
  prone to a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Attackers are able to add or remove wishlist items via a forged
  request granted due to missing or incorrect nonce validation on the wishlist_add and
  wishlist_remove functions.");

  script_tag(name:"affected", value:"WordPress WPC Smart Wishlist for WooCommerce plugin prior to
  version 4.7.2.");

  script_tag(name:"solution", value:"Update to version 4.7.2 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/woo-smart-wishlist/wpc-smart-wishlist-for-woocommerce-467-cross-site-request-forgery-via-wishlist-add-and-wishlist-remove");

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

if( version_is_less( version: version, test_version: "4.7.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.7.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
