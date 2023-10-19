# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wp_extra_file_types_project:wp_extra_file_types";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127563");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-09-25 12:00:45 +0000 (Mon, 25 Sep 2023)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-27 16:49:00 +0000 (Thu, 27 Jan 2022)");

  script_cve_id("CVE-2021-24936");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WP Extra File Types Plugin < 0.5.1 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-extra-file-types/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WP Extra File Types' is prone to a
  cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not have CSRF check when saving its settings,
  nor sanitise and escape some of them, which could allow attackers to make a logged in admin
  change them and perform cross-site scripting (XSS) attacks.");

  script_tag(name:"affected", value:"WordPress WP Extra File Types prior to version 0.5.1.");

  script_tag(name:"solution", value:"Update to version 0.5.1 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/4fb61b84-ff5f-4b4c-a516-54b749f9611e");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "0.5.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "0.5.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
