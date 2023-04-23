# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kriesi:enfold";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124299");
  script_version("2023-04-06T10:08:49+0000");
  script_tag(name:"last_modification", value:"2023-04-06 10:08:49 +0000 (Thu, 06 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-03-29 08:29:25 +0000 (Wed, 29 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-15 16:24:00 +0000 (Fri, 15 Oct 2021)");

  script_cve_id("CVE-2021-24719");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Enfold Theme Plugin < 4.8.4 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_theme_http_detect.nasl");
  script_mandatory_keys("wordpress/theme/enfoldtheme/detected");

  script_tag(name:"summary", value:"The WordPress 'Enfold' theme is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The issue appears when pagination comes in place while
  navigating on a WordPress site with Enfold theme active. When that occurs, the parameter
  'avia-element-paging' appears.");

  script_tag(name:"affected", value:"WordPress Enfold theme prior to version 4.8.4.");

  script_tag(name:"solution", value:"Update to version 4.8.4 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/a53e213f-6011-47f8-93e6-aa5ad30e857e");

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

if( version_is_less( version:version, test_version:"4.8.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"4.8.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
