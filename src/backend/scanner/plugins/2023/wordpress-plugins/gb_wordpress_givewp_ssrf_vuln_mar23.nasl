# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:givewp:givewp";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127661");
  script_version("2023-12-26T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-26 05:05:23 +0000 (Tue, 26 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-19 11:08:03 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-21 19:17:00 +0000 (Thu, 21 Dec 2023)");

  script_cve_id("CVE-2022-40312");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress GiveWP WordPress Plugin < 2.25.2 SSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/give/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'GiveWP' is prone to a server-side
  request forgery (SSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Authenticated attackers with administrator-level privileges are
  able to make web requests to arbitrary locations originating from the web application and can be
  used to query and modify information from internal services via
  give_get_content_by_ajax_handler.");

  script_tag(name:"affected", value:"WordPress GiveWP plugin prior to version 2.25.2.");

  script_tag(name:"solution", value:"Update to version 2.25.2 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/give/wordpress-givewp-plugin-2-25-1-server-side-request-forgery-ssrf-vulnerability");

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

if( version_is_less( version: version, test_version: "2.25.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.25.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
