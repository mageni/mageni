# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:atlas_gondal:export_all_urls";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127552");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-09-14 09:20:45 +0000 (Thu, 14 Sep 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-15 18:53:00 +0000 (Fri, 15 Apr 2022)");

  script_cve_id("CVE-2022-0892", "CVE-2022-0914", "CVE-2022-29452");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Export All URLs Plugin < 4.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/export-all-urls/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Export All URLs' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-0892: The plugin does not sanitise and escape the CSV filename before outputting it
  back in the page, leading to a reflected cross-site scripting

  - CVE-2022-0914: The plugin does not have CSRF in place when exporting data, which could allow
  attackers to make a logged in admin export all posts and pages (including private and draft)
  into an arbitrary CSV file, which the attacker can then download and retrieve the list of titles
  for example

  - CVE-2022-29452: The plugin does not sanitise and escape some parameters, which could allow
  users with a role as low as editor to perform stored cross-site scripting attacks.");

  script_tag(name:"affected", value:"WordPress Export All URLs prior to version 4.2.");

  script_tag(name:"solution", value:"Update to version 4.2 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/e5d95261-a243-493f-be6a-3c15ccb65435");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/c328be28-75dd-43db-a5b9-c1ba0636c930");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/d63a853a-fe10-41d5-8264-0a54d26a2665");

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

if( version_is_less( version: version, test_version: "4.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
