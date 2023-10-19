# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:metaslider:slider%2c_gallery%2c_and_carousel";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127523");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-17 10:04:12 +0000 (Thu, 17 Aug 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-26 20:25:00 +0000 (Wed, 26 Apr 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-1473");

  script_name("WordPress Slider, Gallery, and Carousel by MetaSlider Plugin < 3.29.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/ml-slider/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Slider, Gallery, and Carousel by
  MetaSlider' is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not sanitise and escape a parameter before
  outputting it back in the page.");

  script_tag(name:"affected", value:"WordPress Slider, Gallery, and Carousel by MetaSlider plugin
  prior to version 3.29.1.");

  script_tag(name:"solution", value:"Update to version 3.29.1 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/a6e6c67b-7d9b-4fdb-8115-c33add7bfc3d");

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

if( version_is_less( version: version, test_version: "3.29.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.29.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
