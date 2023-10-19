# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:yikesinc:custom_product_tabs_for_woocommerce";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127525");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-17 13:24:12 +0000 (Thu, 17 Aug 2023)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-21 01:45:00 +0000 (Mon, 21 Nov 2022)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2022-43463");

  script_name("WordPress Custom Product Tabs for WooCommerce Plugin < 1.8.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/yikes-inc-easy-custom-woocommerce-product-tabs/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Custom Product Tabs for WooCommerce' is
  prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"A malicious actor is able to inject malicious scripts, such as
  redirects, advertisements, and other HTML payloads into your website which will be executed when
  guests visit your site.");

  script_tag(name:"affected", value:"WordPress Custom Product Tabs for WooCommerce plugin prior to
  version 1.8.0.");

  script_tag(name:"solution", value:"Update to version 1.8.0 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/yikes-inc-easy-custom-woocommerce-product-tabs/wordpress-custom-product-tabs-for-woocommerce-plugin-1-7-9-auth-stored-cross-site-scripting-xss-vulnerability");

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

if( version_is_less( version: version, test_version: "1.8.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.8.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
