# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:yarpp:yet_another_related_posts_plugin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124304");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-04-14 07:44:07 +0000 (Fri, 14 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-23 04:52:00 +0000 (Thu, 23 Feb 2023)");

  script_cve_id("CVE-2022-4471", "CVE-2022-45374");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress YARPP Plugin < 5.30.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/yet-another-related-posts-plugin/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'YARPP' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2022-4471: The plugin does not validate and escape some of its shortcode attributes before
  outputting them back in a page/post where the shortcode is embed, which could allow users with the
  contributor role and above to perform Stored Cross-Site Scripting attacks.

  Note: CVE-2022-4471 got only partly fixed in 5.30.2 and a final fix for a second attack path was
  included in version 5.30.3.

  - CVE-2022-45374: The plugin does not validate a parameter before using it in an include
  statement, allowing any authenticated users, such as subscriber to perform LFI attacks.");

  script_tag(name:"affected", value:"WordPress YARPP plugin version 5.30.2 and prior.");

  script_tag(name:"solution", value:"Update to version 5.30.3 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/c6cf792b-054c-4d77-bcae-3b700f42130b");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/b34976b3-54c3-45b7-86a0-387ee0a4b680");
  # nb: The changelog mention that the flaw with the id c6cf792b got fixed in 5.30.2 but the
  # advisory itself shows that 5.30.2 only included a partly fix (see insight tag).
  script_xref(name:"URL", value:"https://wordpress.org/plugins/yet-another-related-posts-plugin/#developers");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "5.30.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.30.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
