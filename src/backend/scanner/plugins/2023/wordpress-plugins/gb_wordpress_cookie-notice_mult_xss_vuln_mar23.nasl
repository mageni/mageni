# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hu-manity:cookie_notice_%26_compliance_for_gdpr_%2f_ccpa";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127377");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-03-29 13:02:00 +0000 (Wed, 29 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-10 02:24:00 +0000 (Wed, 10 May 2023)");

  script_cve_id("CVE-2023-0823", "CVE-2023-24400");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Cookie Notice & Compliance for GDPR / CCPA Plugin < 2.4.7 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/cookie-notice/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Cookie Notice & Compliance for
  GDPR / CCPA' is prone to multiple cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-0823: The plugin does not validate and escape some of its shortcode
  attributes before outputting them back in a page/post where the shortcode is embed.

  - CVE-2023-24400: Stored cross-site scripting (XSS) via shortcodes");

  script_tag(name:"affected", value:"WordPress Cookie Notice & Compliance for GDPR / CCPA prior to
  version 2.4.7.");

  script_tag(name:"solution", value:"Update to version 2.4.7 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/83f23a9f-9ace-47d2-a5f3-a4915129b16c");
  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/cookie-notice/wordpress-cookie-notice-compliance-for-gdpr-ccpa-plugin-2-4-6-cross-site-scripting-xss-vulnerability");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port(cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.4.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.4.7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
