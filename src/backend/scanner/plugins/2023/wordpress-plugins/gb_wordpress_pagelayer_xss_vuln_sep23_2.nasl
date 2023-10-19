# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pagelayer:pagelayer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127590");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-17 13:10:11 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2023-4687");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress PageLayer Plugin < 1.7.7 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/pagelayer/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'PageLayer' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin doesn't prevent unauthenticated attackers from
  updating a post's header or footer code on scheduled posts.");

  script_tag(name:"affected", value:"WordPress PageLayer prior to version 1.7.7.");

  script_tag(name:"solution", value:"Update to version 1.7.7 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/31596fc5-4203-40c4-9b0a-e8a37faafddd");

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

if( version_is_less( version: version, test_version: "1.7.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.7.7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
