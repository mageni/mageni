# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:woocommerce:woocommerce";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127684");
  script_version("2024-01-12T16:12:12+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:12 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-10 12:40:45 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-11 19:01:00 +0000 (Thu, 11 Jan 2024)");

  script_cve_id("CVE-2023-52222");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WooCommerce Plugin < 8.3.0 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/woocommerce/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WooCommerce' is prone to a cross-site
  request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"A malicious actor could force higher privileged users to execute
  unwanted actions under their current authentication.");

  script_tag(name:"affected", value:"WordPress WooCommerce prior to version 8.3.0.");

  script_tag(name:"solution", value:"Update to version 8.3.0 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/woocommerce/wordpress-woocommerce-plugin-8-2-2-cross-site-request-forgery-csrf-vulnerability");

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

if( version_is_less( version: version, test_version: "8.3.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.3.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
