# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kadencewp:kadence_woocommerce_email_designer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127614");
  script_version("2023-11-10T16:09:31+0000");
  script_tag(name:"last_modification", value:"2023-11-10 16:09:31 +0000 (Fri, 10 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-09 07:44:07 +0000 (Thu, 09 Nov 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-26 01:41:00 +0000 (Wed, 26 Oct 2022)");

  script_cve_id("CVE-2022-3335");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Kadence WooCommerce Email Designer Plugin < 1.5.7 PHP Object Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/kadence-woocommerce-email-designer/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Kadence WooCommerce Email Designer' is
  prone to a PHP object injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin unserialises the content of an imported file, which
  could lead to PHP object injections issues when an admin import (intentionally or not) a
  malicious file and a suitable gadget chain is present on the blog.");

  script_tag(name:"affected", value:"WordPress Kadence WooCommerce Email Designer plugin prior to
  version 1.5.7.");

  script_tag(name:"solution", value:"Update to version 1.5.7 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/39514705-c887-4a02-a77b-36e1dcca8f5d/");

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

if( version_is_less( version: version, test_version: "1.5.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.5.7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
