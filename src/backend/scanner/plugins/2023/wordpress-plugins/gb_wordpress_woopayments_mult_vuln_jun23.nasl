# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:automattic:woopayments";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127669");
  script_version("2024-01-12T05:05:56+0000");
  script_tag(name:"last_modification", value:"2024-01-12 05:05:56 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"creation_date", value:"2023-12-28 10:20:45 +0000 (Thu, 28 Dec 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-29 06:49:00 +0000 (Fri, 29 Dec 2023)");

  script_cve_id("CVE-2023-35915", "CVE-2023-35916");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WooPayments Plugin < 5.9.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/woocommerce-payments/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WooPayments' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-35915: Authenticated attackers, with shop manager-level access and above are able to
  append additional SQL queries into already existing queries that can be used to extract sensitive
  information from the database.

  - CVE-2023-35916: Unauthenticated attackers are able to change payment information for other
  users' due to a missing capability check on the redirect_pay_for_order_to_update_payment_method
  function.");

  script_tag(name:"affected", value:"WordPress WooPayments prior to version 5.9.1.");

  script_tag(name:"solution", value:"Update to version 5.9.1 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/woocommerce-payments/wordpress-woocommerce-payments-plugin-5-9-0-sql-injection-vulnerability");
  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/woocommerce-payments/wordpress-woocommerce-payments-plugin-5-9-0-insecure-direct-object-references-idor-vulnerability");

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

if( version_is_less( version: version, test_version: "5.9.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.9.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
