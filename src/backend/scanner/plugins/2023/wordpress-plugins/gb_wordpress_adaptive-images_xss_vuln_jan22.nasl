# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nevma:adaptive_images";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170298");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-01-25 20:42:28 +0000 (Wed, 25 Jan 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Adaptive Images Plugin < 0.6.69 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/adaptive-images/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Adaptive Images' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"insight", value:"The plugin does not sanitise and escape the REQUEST_URI before
  outputting it back in a page.");

  script_tag(name:"affected", value:"WordPress Adaptive Images plugin before version 0.6.69.");

  script_tag(name:"solution", value:"Update to version 0.6.69 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/eef137af-408c-481c-8493-afe6ee2105d0");

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

if( version_is_less( version: version, test_version: "0.6.69" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "0.6.69", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
