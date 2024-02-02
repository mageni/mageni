# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress_popular_posts_project:wordpress_popular_posts";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127592");
  script_version("2024-01-09T05:06:46+0000");
  script_tag(name:"last_modification", value:"2024-01-09 05:06:46 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"creation_date", value:"2023-10-19 10:30:39 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-25 01:26:00 +0000 (Wed, 25 Oct 2023)");

  script_cve_id("CVE-2023-45607");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Popular Posts Plugin < 6.3.3 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wordpress-popular-posts/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Popular Posts' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Authenticated attackers are able to inject arbitrary web
  scripts in pages due to insufficient input sanitization and output escaping on user supplied
  attributes.");

  script_tag(name:"affected", value:"WordPress Popular Posts plugin prior to version 6.3.3.");

  script_tag(name:"solution", value:"Update to version 6.3.3 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wordpress-popular-posts/wordpress-popular-posts-632-authenticated-contributor-stored-cross-site-scripting-via-shortcode");

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

if( version_is_less( version: version, test_version: "6.3.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.3.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
