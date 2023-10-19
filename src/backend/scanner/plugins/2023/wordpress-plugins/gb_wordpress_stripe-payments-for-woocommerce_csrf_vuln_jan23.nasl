# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:checkoutplugins:stripe_payments_for_woocommerce";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127396");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-04-17 13:00:00 +0100 (Mon, 17 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-09 14:49:00 +0000 (Thu, 09 Mar 2023)");

  script_cve_id("CVE-2023-23865");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Stripe Payments For WooCommerce Plugin < 1.4.11 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/checkout-plugins-stripe-woo/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Stripe Payments For WooCommerce' is prone
  to a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The settings of the plugin can be changed due to
  cross-site request forgery (CSRF) attacks.");

  script_tag(name:"affected", value:"WordPress Stripe Payments For WooCommerce plugin prior to
  version 1.4.11.");

  script_tag(name:"solution", value:"Update to version 1.4.11 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/checkout-plugins-stripe-woo/wordpress-stripe-payments-for-woocommerce-by-checkout-plugins-plugin-1-4-10-cross-site-request-forgery-csrf-vulnerability");

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

if( version_is_less( version: version, test_version: "1.4.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.4.11", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
