# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:snapcreek:duplicator";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127677");
  script_version("2024-01-10T05:05:17+0000");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-05 09:00:45 +0000 (Fri, 05 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-05 15:08:00 +0000 (Fri, 05 Jan 2024)");

  script_cve_id("CVE-2023-6114");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Duplicator - WordPress Migration Plugin < 1.5.7.1 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/duplicator/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Duplicator - WordPress Migration Plugin'
  is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not disallow listing the 'backups-dup-lite/tmp'
  directory, which temporarily stores files containing sensitive data when directory listing is
  enabled in the web server.");

  script_tag(name:"impact", value:"Unauthenticated attackers are able to discover and access these
  sensitive files, which include a full database dump and a zip archive of the site.");

  script_tag(name:"affected", value:"WordPress Duplicator - WordPress Migration Plugin prior to
  version 1.5.7.1.");

  script_tag(name:"solution", value:"Update to version 1.5.7.1 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/5c5d41b9-1463-4a9b-862f-e9ee600ef8e1");
  script_xref(name:"URL", value:"https://research.cleantalk.org/cve-2023-6114-duplicator-poc-exploit/");

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

if( version_is_less( version: version, test_version: "1.5.7.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.5.7.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
