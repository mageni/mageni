# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:premio:mystickymenu";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127631");
  script_version("2023-11-24T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-11-24 05:05:36 +0000 (Fri, 24 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-21 12:00:51 +0000 (Tue, 21 Nov 2023)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-10 00:45:00 +0000 (Tue, 10 Aug 2021)");

  script_cve_id("CVE-2021-24425");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress My Sticky Bar Plugin < 2.5.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/mystickymenu/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'My Sticky Bar' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not sanitise or escape its Bar Text settings,
  allowing high privilege users to use malicious JavaScript in it, leading to a stored cross-site
  scripting (XSS) issue, which will be triggered in the plugin's setting, as well as all front-page
  of the blog (when the Welcome bar is active).");

  script_tag(name:"affected", value:"WordPress My Sticky Bar plugin prior to version 2.5.2.");

  script_tag(name:"solution", value:"Update to version 2.5.2 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/14632fa8-597e-49ff-8583-9797208a3583/");

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

if( version_is_less( version: version, test_version: "2.5.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.5.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
