# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cartflows:funnel_builder";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127492");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-07-06 07:35:49 +0000 (Thu, 06 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-01 04:15:00 +0000 (Sat, 01 Jul 2023)");

  script_cve_id("CVE-2020-36736");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WooCommerce Checkout & Funnel Builder Plugin < 1.5.16 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/cartflows/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WooCommerce Checkout & Funnel Builder
  by CartFlows' is prone to a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker is able to import/export settings and trigger logs
  showing due to missing or incorrect nonce validation on the export_json, import_json, and
  status_logs_file functions.");

  script_tag(name:"affected", value:"WordPress WooCommerce Checkout & Funnel Builder by CartFlows
  plugin prior to version 1.5.16.");

  script_tag(name:"solution", value:"Update to version 1.5.16 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/0d98c849-4178-4cee-846b-2c136bc56daf");

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

if( version_is_less( version: version, test_version: "1.5.16" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.5.16", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
