# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomunited:wp_meta_seo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124320");
  script_version("2023-05-12T10:50:26+0000");
  script_tag(name:"last_modification", value:"2023-05-12 10:50:26 +0000 (Fri, 12 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-11 17:28:06 +0000 (Thu, 11 May 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-0876");

  script_name("WordPress WP Meta SEO Plugin < 4.5.3 Open Redirect Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-meta-seo/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WP Meta SEO' is prone to an open redirect
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not authorize several ajax actions, allowing
  low-privilege users to make updates to certain data and leading to an arbitrary redirect vulnerability.");

  script_tag(name:"affected", value:"WordPress WP Meta SEO plugin prior to version 4.5.3.");

  script_tag(name:"solution", value:"Update to version 4.5.3 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/1a8c97f9-98fa-4e29-b7f7-bb9abe0c42ea");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"4.5.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"4.5.3", install_path:location );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
