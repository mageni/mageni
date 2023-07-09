# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:strategy11:formidable_form_builder";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127480");
  script_version("2023-06-30T05:06:12+0000");
  script_tag(name:"last_modification", value:"2023-06-30 05:06:12 +0000 (Fri, 30 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-29 08:22:41 +0000 (Thu, 29 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2023-2877");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Formidable Forms Plugin < 6.3.1 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/formidable/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Formidable Forms' is prone to a
  remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not adequately authorize the user or validate
  the plugin URL in its functionality for installing add-ons.");

  script_tag(name:"affected", value:"WordPress Formidable Forms prior to version 6.3.1.");

  script_tag(name:"solution", value:"Update to version 6.3.1 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/33765da5-c56e-42c1-83dd-fcaad976b402");

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

if( version_is_less( version: version, test_version: "6.3.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.3.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
