# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google_xml_sitemaps_project:google_xml_sitemaps";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127570");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-03 12:30:00 +0000 (Tue, 03 Oct 2023)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-30 14:24:00 +0000 (Thu, 30 Jun 2022)");

  script_cve_id("CVE-2021-25088");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress XML Sitemap Generator for Google Plugin < 4.1.3 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/google-sitemap-generator/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'XML Sitemap Generator for Google' is
  prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not sanitise and escape a settings before
  outputting it in the Debug page, which could allow high privilege users such as editor and above
  to perform cross-site scripting (XSS) attacks even when the unfiltered_html is disallowed.");

  script_tag(name:"affected", value:"WordPress XML Sitemap Generator for Google plugin prior to
  version 4.1.3.");

  script_tag(name:"solution", value:"Update to version 4.1.3 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/820c51d6-186e-4d63-b4a7-bd0a59c02cc8");

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

if( version_is_less( version: version, test_version: "4.1.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.1.3", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
