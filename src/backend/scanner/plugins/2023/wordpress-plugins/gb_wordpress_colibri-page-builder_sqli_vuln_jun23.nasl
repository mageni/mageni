# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:extendthemes:colibri_page_builder";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127562");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-09-22 08:00:45 +0000 (Fri, 22 Sep 2023)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-05 19:13:00 +0000 (Tue, 05 Sep 2023)");

  script_cve_id("CVE-2023-2188");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Colibri Page Builder Plugin < 1.0.229 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/colibri-page-builder/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Colibri Page Builder' is prone to an
  SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Authenticated attackers with administrator-level privileges are
  able to append additional SQL queries into already existing queries that can be used to extract
  sensitive information from the database due to insufficient escaping on the user supplied
  parameter and lack of sufficient preparation on the existing SQL query.");

  script_tag(name:"affected", value:"WordPress Colibri Page Builder prior to version 1.0.229.");

  script_tag(name:"solution", value:"Update to version 1.0.229 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/c73d4b78-72aa-409a-a787-898179773b82");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.0.229" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.0.229", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
