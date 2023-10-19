# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:exactmetrics:exactmetrics";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124402");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-09 08:12:46 +0000 (Wed, 09 Aug 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-10 03:53:00 +0000 (Thu, 10 Aug 2023)");

  script_cve_id("CVE-2023-23880");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress ExactMetrics Plugin < 7.14.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/google-analytics-dashboard-for-wp/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'ExactMetrics' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This could allow a malicious actor to inject malicious scripts,
  such as redirects, advertisements, and other HTML payloads into your website which will be
  executed when guests visit your site.");

  script_tag(name:"affected", value:"WordPress ExactMetrics plugin prior to version 7.14.2.");

  script_tag(name:"solution", value:"Update to version 7.14.2 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/google-analytics-dashboard-for-wp/wordpress-exactmetrics-plugin-7-14-1-cross-site-scripting-xss-vulnerability");

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

if( version_is_less( version: version, test_version: "7.14.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.14.2", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

