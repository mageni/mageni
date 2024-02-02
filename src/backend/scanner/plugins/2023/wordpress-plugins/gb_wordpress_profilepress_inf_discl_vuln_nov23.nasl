# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:properfraction:profilepress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124487");
  script_version("2023-12-08T16:09:30+0000");
  script_tag(name:"last_modification", value:"2023-12-08 16:09:30 +0000 (Fri, 08 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-05 07:10:51 +0000 (Tue, 05 Dec 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-06 01:44:00 +0000 (Wed, 06 Dec 2023)");

  script_cve_id("CVE-2023-44150");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress ProfilePress Plugin < 4.13.3 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-user-avatar/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'ProfilePress (Formerly WP User Avatar)'
  is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Exposure of sensitive information to an unauthorized actor");

  script_tag(name:"affected", value:"WordPress ProfilePress plugin prior to version 4.13.3.");

  script_tag(name:"solution", value:"Update to version 4.13.3 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/wp-user-avatar/wordpress-profilepress-plugin-4-13-2-sensitive-data-exposure-via-debug-log-vulnerability");

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

if( version_is_less( version: version, test_version: "4.13.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.13.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
