# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dfactory:responsive_lightbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126622");
  script_version("2023-12-20T12:22:41+0000");
  script_tag(name:"last_modification", value:"2023-12-20 12:22:41 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-18 12:30:12 +0000 (Mon, 18 Dec 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-19 19:49:00 +0000 (Tue, 19 Dec 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-49174");

  script_name("WordPress Responsive Lightbox & Gallery Plugin < 2.4.6 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/responsive-lightbox/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Responsive Lightbox & Gallery' is prone
  to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Stored cross-site scripting via the 'name' parameter.");

  script_tag(name:"affected", value:"WordPress Responsive Lightbox & Gallery plugin prior to version 2.4.6.");

  script_tag(name:"solution", value:"Update to version 2.4.6 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/responsive-lightbox/responsive-lightbox-245-authenticated-author-stored-cross-site-scripting-via-name");

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

if( version_is_less( version: version, test_version: "2.4.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.4.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
