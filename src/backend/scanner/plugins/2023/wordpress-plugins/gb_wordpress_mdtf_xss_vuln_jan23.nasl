# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pluginus:wordpress_meta_data_and_taxonomies_filter";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126469");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-29 08:03:12 +0000 (Tue, 29 Aug 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-28 21:37:00 +0000 (Tue, 28 Mar 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-28664");

  script_name("WordPress Meta Data and Taxonomies Filter Plugin < 1.3.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-meta-data-filter-and-taxonomy-filter/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Meta Data and Taxonomies Filter' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin appears to have an incorrect usage of the core
  function 'esc_html__' which can lead to a reflected XSS via the 'tax_name' parameter.");

  script_tag(name:"affected", value:"WordPress Meta Data and Taxonomies Filter plugin prior to
  version 1.3.1.");

  script_tag(name:"solution", value:"Update to version 1.3.1 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/research/tra-2023-3");

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

if( version_is_less( version: version, test_version: "1.3.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.3.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
