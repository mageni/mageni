# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:brainstormforce:starter_templates";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127655");
  script_version("2023-12-15T16:10:08+0000");
  script_tag(name:"last_modification", value:"2023-12-15 16:10:08 +0000 (Fri, 15 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-13 07:00:45 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-12 16:59:00 +0000 (Tue, 12 Dec 2023)");

  script_cve_id("CVE-2023-41804");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Starter Templates Plugin < 3.2.5 SSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/astra-sites/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Starter Templates' is prone to a
  server-side request forgery (SSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Authenticated attackers, with contributor-level access and
  above, to make web requests to arbitrary locations originating from the web application and can
  be used to query and modify information from internal services via remote_request.");

  script_tag(name:"affected", value:"WordPress Starter Templates prior to version 3.2.5.");

  script_tag(name:"solution", value:"Update to version 3.2.5 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/astra-sites/wordpress-starter-templates-plugin-3-2-4-server-side-request-forgery-ssrf-vulnerability");

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

if( version_is_less_equal( version: version, test_version: "3.2.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
