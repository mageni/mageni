# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elementor:elementor_pro";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127653");
  script_version("2023-12-14T08:20:35+0000");
  script_tag(name:"last_modification", value:"2023-12-14 08:20:35 +0000 (Thu, 14 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-08 07:29:45 +0000 (Fri, 08 Dec 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-13 18:46:00 +0000 (Tue, 13 Jun 2023)");

  script_cve_id("CVE-2023-3124");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Elementor Pro Plugin < 3.11.7 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/elementor-pro/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Elementor Pro' is prone to a privilege
  escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Authenticated attackers with subscriber-level capabilities are
  able to update arbitrary site options.");

  script_tag(name:"insight", value:"Lack of a capability check to restrict access to a high
  privileged user only and missing user input validation in '/modules/woocommerce/module.php' in
  update_page_option function.");

  script_tag(name:"affected", value:"WordPress Elementor Pro prior to version 3.11.7.");

  script_tag(name:"solution", value:"Update to version 3.11.7 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/570474f2-c118-45e1-a237-c70b849b2d3c");

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

if( version_is_less( version: version, test_version: "3.11.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.11.7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
