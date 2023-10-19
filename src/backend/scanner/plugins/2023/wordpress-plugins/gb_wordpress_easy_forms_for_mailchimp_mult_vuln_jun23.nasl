# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:yikesinc:easy_forms_for_mailchimp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126417");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-06-16 10:24:53 +0000 (Fri, 16 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-05 14:59:00 +0000 (Mon, 05 Jun 2023)");

  script_cve_id("CVE-2023-1323", "CVE-2023-2518");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Easy Forms for Mailchimp Plugin < 6.8.9 Multiple Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/yikes-inc-easy-mailchimp-extender/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Easy Forms for Mailchimp' is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-1323: The plugin does not sanitise and escape some of its from parameters, which could
  allow high privilege users such as admin to perform Stored Cross-Site Scripting attacks even when
  the unfiltered_html capability is disallowed (for example in multisite setup).

  - CVE-2023-2518: The plugin does not sanitise and escape a parameter before outputting it back
  in the page when the debug option is enabled, leading to a Reflected Cross-Site Scripting which
  could be used against high privilege users such as admin.");

  script_tag(name:"affected", value:"WordPress Easy Forms for Mailchimp plugin prior to
  version 6.8.9.");

  script_tag(name:"solution", value:"Update to version 6.8.9 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/d3a2af00-719c-4b86-8877-b1d68a589192");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/ca120255-2c50-4906-97f3-ea660486db4c");


  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos[ "version" ];
location = infos[ "location" ];

if( version_is_less( version: version, test_version: "6.8.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.8.9", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
