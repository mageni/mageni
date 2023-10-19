# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpchill:customizable_wordpress_gallery_plugin_-_modula_image_gallery";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126272");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-04-25 09:05:31 +0200 (Tue, 25 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-23 19:37:00 +0000 (Wed, 23 Nov 2022)");

  script_cve_id("CVE-2022-41135");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Modula Image Gallery Plugin < 2.6.91 Broken Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/modula-best-grid-gallery/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Modula Image Gallery' is prone to a
  broken access control vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Modula Image Gallery plugin prior to version 2.6.91.");

  script_tag(name:"solution", value:"Update to version 2.6.91 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/modula-best-grid-gallery/wordpress-modula-plugin-2-6-9-unauth-plugin-settings-change-vulnerability");

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

if( version_is_less( version: version, test_version: "2.6.91" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.6.91", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
