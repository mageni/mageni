# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elementor:website_builder";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127519");
  script_version("2023-08-16T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-08-16 05:05:28 +0000 (Wed, 16 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-15 08:10:38 +0000 (Tue, 15 Aug 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2022-4953");

  script_name("WordPress Elementor Website Builder Plugin < 3.5.5 Iframe Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/elementor/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Elementor Website Builder' is prone to an
  iframe injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not filter out user-controlled URLs from being
  loaded into the DOM. This could be used to inject rogue iframes that point to malicious URLs.");

  script_tag(name:"affected", value:"WordPress Elementor Website Builder plugin prior to version
  3.5.5.");

  script_tag(name:"solution", value:"Update to version 3.5.5 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/8273357e-f9e1-44bc-8082-8faab838eda7");

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

if( version_is_less( version: version, test_version: "3.5.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.5.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
