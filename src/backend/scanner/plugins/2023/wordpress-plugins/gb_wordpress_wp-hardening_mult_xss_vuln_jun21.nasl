# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:getastra:wp_hardening";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126490");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-09-25 10:00:11 +0000 (Mon, 25 Sep 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-25 12:42:00 +0000 (Fri, 25 Jun 2021)");

  script_cve_id("CVE-2021-24372", "CVE-2021-24373");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WP Hardening Plugin < 1.2.2 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-security-hardening/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WP Hardening' is prone to multiple
  cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  CVE-2021-24372: Plugin did not sanitise or escape the $_SERVER['REQUEST_URI'] before outputting
  it in an attribute, leading to a reflected Cross-Site Scripting issue.

  CVE-2021-24373: Plugin did not sanitise or escape the historyvalue GET parameter before
  outputting it in a Javascript block, leading to a reflected Cross-Site Scripting issue.");

  script_tag(name:"affected", value:"WordPress WP Hardening prior to version 1.2.2.");

  script_tag(name:"solution", value:"Update to version 1.2.2 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wp-security-hardening/wp-hardening-fix-your-wordpress-security-121-reflected-cross-site-scripting");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wp-security-hardening/wp-hardening-fix-your-wordpress-security-121-reflected-cross-site-scripting-2");

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

if( version_is_less( version: version, test_version: "1.2.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.2.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
