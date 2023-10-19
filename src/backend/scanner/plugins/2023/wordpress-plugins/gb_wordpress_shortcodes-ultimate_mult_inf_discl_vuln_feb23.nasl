# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:getshortcodes:shortcodes_ultimate";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127370");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-03-22 07:01:55 +0000 (Wed, 22 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-23 18:19:00 +0000 (Thu, 23 Mar 2023)");

  script_cve_id("CVE-2023-0890", "CVE-2023-0911");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Shortcodes Ultimate Plugin < 5.12.8 Multiple Information Disclosure vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/shortcodes-ultimate/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Shortcodes Ultimate' is prone to multiple
  information disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-0890: The plugin does not ensure that posts to be displayed via some shortcodes are
  already public and can be accessed by the user making the request, allowing any authenticated
  users such as subscriber to view draft, private or even password protected posts. It is also
  possible to leak the password of protected posts.

  - CVE-2023-0911: The plugin does not validate the user meta to be retrieved via the user
  shortcode, allowing any authenticated users such as subscriber to retrieve arbitrary user meta
  (except the user_pass), such as the user email and activation key by default.");

  script_tag(name:"affected", value:"WordPress Shortcodes Ultimate plugin prior to
  version 5.12.8.");

  script_tag(name:"solution", value:"Update to version 5.12.8 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/8a466f15-f112-4527-8b02-4544a8032671");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/35404d16-7213-4293-ac0d-926bd6c17444");

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

if( version_is_less( version: version, test_version: "5.12.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.12.8", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
