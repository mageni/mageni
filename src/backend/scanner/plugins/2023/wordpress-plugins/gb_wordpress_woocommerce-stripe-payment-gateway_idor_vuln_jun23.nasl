# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:woocommerce:stripe_payment_gateway";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127477");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-06-21 21:35:51 +0200 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-21 21:06:00 +0000 (Wed, 21 Jun 2023)");

  script_cve_id("CVE-2023-34000");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WooCommerce Stripe Payment Gateway Plugin < 7.4.1 IDOR Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/woocommerce-gateway-stripe/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WooCommerce Stripe Payment Gateway' is
  prone to an insecure direct object references (IDOR) vulnerability.");

  script_tag(name:"impact", value:"The plugin allows any unauthenticated user to view any
  WooCommnerce order's PII data including email, user's name, and full address.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress WooCommerce Stripe Payment Gateway plugin prior to version 7.4.1.");

  script_tag(name:"solution", value:"Update to version 7.4.1 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/woocommerce-gateway-stripe/wordpress-woocommerce-stripe-payment-gateway-plugin-7-4-0-insecure-direct-object-references-idor-vulnerability");
  script_xref(name:"URL", value:"https://patchstack.com/articles/unauthenticated-idor-to-pii-disclosure-vulnerability-in-woocommerce-stripe-gateway-plugin");

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

if( version_is_less( version: version, test_version: "7.4.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.4.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
