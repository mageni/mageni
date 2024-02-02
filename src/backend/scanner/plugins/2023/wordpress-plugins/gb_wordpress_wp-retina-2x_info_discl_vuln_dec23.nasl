# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:meowapps:wp_retina_2x";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124494");
  script_version("2024-01-05T05:05:19+0000");
  script_tag(name:"last_modification", value:"2024-01-05 05:05:19 +0000 (Fri, 05 Jan 2024)");
  script_tag(name:"creation_date", value:"2023-12-22 08:21:10 +0000 (Fri, 22 Dec 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-02 16:03:00 +0000 (Tue, 02 Jan 2024)");

  script_cve_id("CVE-2023-44982");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WP Retina 2x Plugin < 6.4.6 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-retina-2x/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WP Retina 2x' is prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Exposure of sensitive information to an unauthorized actor.");

  script_tag(name:"affected", value:"WordPress WP Retina 2x plugin prior to version 6.4.6.");

  script_tag(name:"solution", value:"Update to version 6.4.6 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/wp-retina-2x/wordpress-wp-retina-2x-plugin-6-4-5-sensitive-data-exposure-via-log-file-vulnerability");

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

if( version_is_less( version: version, test_version: "6.4.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.4.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
