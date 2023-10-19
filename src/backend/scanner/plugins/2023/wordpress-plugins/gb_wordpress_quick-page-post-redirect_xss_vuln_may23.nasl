# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:quick_page%2fpost_redirect_project:quick_page%2fpost_redirect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127512");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-09 08:13:12 +0000 (Wed, 09 Aug 2023)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-10 03:52:00 +0000 (Thu, 10 Aug 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-25063");

  script_name("WordPress Quick Page/Post Redirect Plugin < 5.2.4 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/quick-pagepost-redirect-plugin/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Quick Page/Post Redirect Plugin' is prone
  to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not sanitise and escape some of its settings,
  which could allow high privilege users such as admin to perform stored cross-site scripting (XSS)
  attacks even when the unfiltered_html capability is disallowed.");

  script_tag(name:"affected", value:"WordPress Quick Page/Post Redirect plugin prior to version
  5.2.4.");

  script_tag(name:"solution", value:"Update to version 5.2.4 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/quick-pagepost-redirect-plugin/wordpress-quick-page-post-redirect-plugin-plugin-5-2-3-cross-site-scripting-xss");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/46fc0b5c-25ee-481d-8e65-8e0b0a787601");

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

if( version_is_less( version: version, test_version: "5.2.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.2.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
