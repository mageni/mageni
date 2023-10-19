# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:royal-elementor-addons:royal_elementor_addons";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126361");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-04-25 13:14:31 +0200 (Tue, 25 Apr 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-13 07:56:00 +0000 (Fri, 13 Jan 2023)");

  script_cve_id("CVE-2022-4700", "CVE-2022-4701", "CVE-2022-4702", "CVE-2022-4703",
                "CVE-2022-4704", "CVE-2022-4705", "CVE-2022-4707", "CVE-2022-4708",
                "CVE-2022-4709", "CVE-2022-4710", "CVE-2022-4711");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress The Royal Elementor Addons Plugin < 1.3.60 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/royal-elementor-addons/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'The Royal Elementor Addons' is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-4700: Insufficient access control in the 'wpr_activate_required_theme' AJAX action

  - CVE-2022-4701: Insufficient access control in the 'wpr_activate_required_plugins' AJAX action

  - CVE-2022-4702: Insufficient access control in the 'wpr_fix_royal_compatibility' AJAX action

  - CVE-2022-4703: Insufficient access control in the 'wpr_reset_previous_import' AJAX action

  - CVE-2022-4704: Insufficient access control in the 'wpr_import_templates_kit' AJAX action

  - CVE-2022-4705: Insufficient access control in the 'wpr_final_settings_setup' AJAX action

  - CVE-2022-4707: Due to missing nonce validation in the 'wpr_create_mega_menu_template' AJAX
  function it is possible to perform cross-site request foregery.

  - CVE-2022-4708: Insufficient access control in the 'wpr_save_template_conditions' AJAX action

  - CVE-2022-4709: Insufficient access control in the 'wpr_import_library_template' AJAX action

  - CVE-2022-4710: Due to insufficient input sanitization and output escaping of the
  'wpr_ajax_search_link_target' parameter in the 'data_fetch' function it is possible to perform
  reflected cross-site scripting.

  - CVE-2022-4711: Insufficient access control in the 'wpr_save_mega_menu_settings' AJAX action");

  script_tag(name:"affected", value:"WordPress The Royal Elementor Addons plugin prior to
  version 1.3.60.");

  script_tag(name:"solution", value:"Update to version 1.3.60 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2023/01/eleven-vulnerabilities-patched-in-royal-elementor-addons/");

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

if( version_is_less( version: version, test_version: "1.3.60" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.3.60", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
