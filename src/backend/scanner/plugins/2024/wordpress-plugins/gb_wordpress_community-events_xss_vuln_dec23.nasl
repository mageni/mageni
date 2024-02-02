# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:community_events_project:community_events";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126655");
  script_version("2024-01-19T16:09:33+0000");
  script_tag(name:"last_modification", value:"2024-01-19 16:09:33 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-09 11:15:31 +0200 (Tue, 09 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-10 16:51:00 +0000 (Tue, 10 Aug 2021)");

  script_cve_id("CVE-2021-24496");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Community Events Plugin < 1.4.8 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/community-events/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Community Events' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not sanitise, validate or escape its
  importrowscount and successimportcount GET parameters before outputting them back in an admin
  page, leading to a reflected cross-site scripting issue which will be executed in the context of
  a logged in administrator.");

  script_tag(name:"affected", value:"WordPress Community Events plugin prior to version 1.4.8.");

  script_tag(name:"solution", value:"Update to version 1.4.8 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/5fd1cb7f-a036-4c5b-9557-0ffd4ef6b834/");

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

if( version_is_less( version: version, test_version: "1.4.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.4.8", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
