# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:brainstormforce:spectra";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126579");
  script_version("2023-12-26T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-26 05:05:23 +0000 (Tue, 26 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-20 09:30:48 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-18 19:14:00 +0000 (Mon, 18 Dec 2023)");

  script_cve_id("CVE-2023-49833");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Spectra - WordPress Gutenberg Blocks Plugin < 2.7.10 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/ultimate-addons-for-gutenberg/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Spectra - WordPress Gutenberg Blocks' is
  prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Authenticated attackers, with contributor-level access and
  above, could inject arbitrary web scripts in pages that will execute whenever a user accesses an
  injected page.");

  script_tag(name:"affected", value:"WordPress Spectra - WordPress Gutenberg Blocks plugin prior to
  version 2.7.10.");

  script_tag(name:"solution", value:"Update to version 2.7.10 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/ultimate-addons-for-gutenberg/wordpress-spectra-plugin-2-7-9-cross-site-scripting-xss-vulnerability");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.7.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.7.10", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
