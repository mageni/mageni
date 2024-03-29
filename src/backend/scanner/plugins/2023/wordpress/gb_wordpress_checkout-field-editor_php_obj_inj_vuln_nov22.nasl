# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:themehigh:checkout_field_editor_for_woocommerce";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127507");
  script_version("2023-08-04T05:06:23+0000");
  script_tag(name:"last_modification", value:"2023-08-04 05:06:23 +0000 (Fri, 04 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-02 08:30:03 +0000 (Wed, 02 Aug 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2022-3490");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Checkout Field Editor (Checkout Manager) for WooCommerce Plugin < 1.8.0 PHP Object Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/woo-checkout-field-editor-pro/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Checkout Field Editor (Checkout Manager)
  for WooCommerce' is prone to a PHP object injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin unserialize user input provided via the settings,
  which could allow high privilege users such as admin to perform PHP Object Injection when a
  suitable gadget is present.");

  script_tag(name:"affected", value:"WordPress Checkout Field Editor (Checkout Manager) for
  WooCommerce plugin prior to version 1.8.0.");

  script_tag(name:"solution", value:"Update to version 1.8.0 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/0c9f22e0-1d46-4957-9ba5-5cca78861136");

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

if( version_is_less( version: version, test_version: "1.8.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.8.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
