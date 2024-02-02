# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pluginus:husky_-_products_filter_professional_for_woocommerce";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127665");
  script_version("2023-12-29T05:06:34+0000");
  script_tag(name:"last_modification", value:"2023-12-29 05:06:34 +0000 (Fri, 29 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-22 12:20:45 +0000 (Fri, 22 Dec 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-22 09:54:00 +0000 (Fri, 22 Dec 2023)");

  script_cve_id("CVE-2023-40010");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress HUSKY - Products Filter for WooCommerce Professional Plugin < 1.3.4.3 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/woocommerce-products-filter/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'HUSKY - Products Filter for WooCommerce
  Professional' is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Unauthenticated attackers are able to append additional SQL
  queries into already existing queries that can be used to extract sensitive information from the
  database.");

  script_tag(name:"insight", value:"Insufficient escaping on the user supplied parameter and lack
  of sufficient preparation on the existing SQL query.");

  script_tag(name:"affected", value:"WordPress HUSKY - Products Filter for WooCommerce Professional
  prior to version 1.3.4.3.");

  script_tag(name:"solution", value:"Update to version 1.3.4.3 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/woocommerce-products-filter/wordpress-husky-plugin-1-3-4-2-sql-injection-vulnerability");

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

if( version_is_less( version: version, test_version: "1.3.4.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.3.4.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
