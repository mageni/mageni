# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:seedprod:website_builder_by_seedprod";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127630");
  script_version("2023-11-24T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-11-24 05:05:36 +0000 (Fri, 24 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-21 10:20:51 +0000 (Tue, 21 Nov 2023)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-29 20:15:00 +0000 (Wed, 29 Jul 2020)");

  script_cve_id("CVE-2020-15038");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Website Builder by SeedProd Plugin < 5.1.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/coming-soon/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Website Builder by SeedProd' is prone to
  a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Headline field under the Page Settings section along with
  other fields in the plugin settings are vulnerable to stored XSS, which gets triggered when the
  Coming Soon page is displayed (both in preview mode and live).");

  script_tag(name:"affected", value:"WordPress Website Builder by SeedProd plugin prior to version
  5.1.2.");

  script_tag(name:"solution", value:"Update to version 5.1.2 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/coming-soon/coming-soon-page-by-seedprod-511-authenticated-stored-cross-site-scripting");

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

if( version_is_less( version: version, test_version: "5.1.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.1.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
