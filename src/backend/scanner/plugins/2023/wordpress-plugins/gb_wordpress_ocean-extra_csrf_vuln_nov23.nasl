# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oceanwp:ocean_extra";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127664");
  script_version("2023-12-29T16:09:56+0000");
  script_tag(name:"last_modification", value:"2023-12-29 16:09:56 +0000 (Fri, 29 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-21 07:20:45 +0000 (Thu, 21 Dec 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-22 09:54:00 +0000 (Fri, 22 Dec 2023)");

  script_cve_id("CVE-2023-49164");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Ocean Extra Plugin < 2.2.3 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/ocean-extra/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Ocean Extra' is prone to a cross-site
  request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Unauthenticated attackers are able to activate arbitrary plugins
  via a forged request granted.");

  script_tag(name:"insight", value:"Missing or incorrect nonce validation on the
  ajax_required_plugins_activate() function.");

  script_tag(name:"affected", value:"WordPress Ocean Extra prior to version 2.2.3.");

  script_tag(name:"solution", value:"Update to version 2.2.3 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/ocean-extra/wordpress-ocean-extra-plugin-2-2-2-csrf-leading-to-arbitrary-plugin-activation-vulnerability");

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

if( version_is_less( version: version, test_version: "2.2.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
