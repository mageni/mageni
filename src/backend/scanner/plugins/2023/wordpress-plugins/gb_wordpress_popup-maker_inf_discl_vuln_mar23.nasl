# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:code-atlantic:popup_maker";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127666");
  script_version("2023-12-29T16:09:56+0000");
  script_tag(name:"last_modification", value:"2023-12-29 16:09:56 +0000 (Fri, 29 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-27 06:20:45 +0000 (Wed, 27 Dec 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-27 20:24:00 +0000 (Wed, 27 Dec 2023)");

  script_cve_id("CVE-2022-47597");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Popup Maker Plugin < 1.18.0 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/popup-maker/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Popup Maker' is prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Unauthenticated attackers are able to view log files.");

  script_tag(name:"insight", value:"The plugin generates a predictable name when creating debug log
  files.");

  script_tag(name:"affected", value:"WordPress Popup Maker prior to version 1.18.0.");

  script_tag(name:"solution", value:"Update to version 1.18.0 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/popup-maker/wordpress-popup-maker-plugin-1-17-1-unauth-access-to-debug-log");

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

if( version_is_less( version: version, test_version: "1.18.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.18.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
