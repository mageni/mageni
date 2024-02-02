# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kadencewp:kadence_woocommerce_email_designer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127615");
  script_version("2023-11-16T05:05:14+0000");
  script_tag(name:"last_modification", value:"2023-11-16 05:05:14 +0000 (Thu, 16 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-09 10:44:07 +0000 (Thu, 09 Nov 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-14 16:23:00 +0000 (Tue, 14 Nov 2023)");

  script_cve_id("CVE-2023-47186");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Kadence WooCommerce Email Designer Plugin < 1.5.12 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/kadence-woocommerce-email-designer/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Kadence WooCommerce Email Designer' is
  prone to a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Attackers are able to send test emails and reset the plugin's
  settings via a forged request granted due to missing or incorrect nonce validation on the
  ajax_reset() and ajax_send_email() functions.");

  script_tag(name:"affected", value:"WordPress Kadence WooCommerce Email Designer plugin prior to
  version 1.5.12.");

  script_tag(name:"solution", value:"Update to version 1.5.12 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/kadence-woocommerce-email-designer/wordpress-kadence-woocommerce-email-designer-plugin-1-5-11-cross-site-request-forgery-csrf-vulnerability");

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

if( version_is_less( version: version, test_version: "1.5.12" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.5.12", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
