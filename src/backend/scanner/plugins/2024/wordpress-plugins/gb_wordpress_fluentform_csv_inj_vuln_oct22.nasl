# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:fluentforms:contact_form";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124499");
  script_version("2024-01-12T05:05:56+0000");
  script_tag(name:"last_modification", value:"2024-01-12 05:05:56 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-02 08:30:48 +0000 (Tue, 02 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-09 20:09:00 +0000 (Wed, 09 Nov 2022)");

  script_cve_id("CVE-2022-3463");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Contact Form Plugin < 4.3.13 CSV Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/fluentform/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Contact Form' is prone to a CSV
  injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not validate and escape fields when exporting
  form entries as CSV, leading to a CSV injection.");

  script_tag(name:"affected", value:"WordPress Contact Form plugin prior to version 4.3.13.");

  script_tag(name:"solution", value:"Update to version 4.3.13 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/e2a59481-db45-4b8e-b17a-447303469364");

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

if( version_is_less( version: version, test_version: "4.3.13" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.3.13", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
