# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:themekraft:buddyforms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126457");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-23 07:03:12 +0000 (Wed, 23 Aug 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-03 16:46:00 +0000 (Fri, 03 Mar 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-26326");

  script_name("WordPress BuddyForms Plugin < 2.7.8 Object Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/buddyforms/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'BuddyForms' is prone to an object
  injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not validate the url parameter of its
  upload_image_from_url AJAX action, which could allow unauthenticated attackers to perform PHAR
  deserialisation granted they an upload a file to the server and a suitable gadget chain is
  present as well.");

  script_tag(name:"affected", value:"WordPress BuddyForms plugin prior to version 2.7.8.");

  script_tag(name:"solution", value:"Update to version 2.7.8 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/a554091e-39d1-4e7e-bbcf-19b2a7b8e89f");

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

if( version_is_less( version: version, test_version: "2.7.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.7.8", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
