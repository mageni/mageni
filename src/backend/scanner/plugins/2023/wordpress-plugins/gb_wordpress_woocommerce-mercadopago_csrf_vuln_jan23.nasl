# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mercadopago:mercado_pago_payments_for_woocommerce";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124326");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-05-23 13:00:00 +0100 (Tue, 23 May 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-08 20:02:00 +0000 (Wed, 08 Mar 2023)");

  script_cve_id("CVE-2022-45068");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Mercado Pago payments for WooCommerce Plugin < 6.4.0 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/woocommerce-mercadopago/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Mercado Pago payments for WooCommerce' is
  prone to a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"This could allow a malicious actor to force higher privileged
  users to execute unwanted actions under their current authentication");

  script_tag(name:"affected", value:"WordPress Mercado Pago payments for WooCommerce prior to
  version 6.4.0.");

  script_tag(name:"solution", value:"Update to version 6.4.0 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/woocommerce-mercadopago/wordpress-mercado-pago-payments-for-woocommerce-plugin-6-3-1-cross-site-request-forgery-csrf-vulnerability?_s_id=cve");

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

if( version_is_less( version: version, test_version: "6.4.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.4.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
