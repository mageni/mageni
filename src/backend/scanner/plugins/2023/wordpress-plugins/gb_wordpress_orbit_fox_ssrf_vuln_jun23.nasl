# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:themeisle:orbitfox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126430");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-06-19 08:11:11 +0000 (Mon, 19 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-05 14:55:00 +0000 (Mon, 05 Jun 2023)");

  script_cve_id("CVE-2023-2287");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Orbit Fox by ThemeIsle Plugin < 2.10.24 SSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/themeisle-companion/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Orbit Fox by ThemeIsle' is prone to a
  server-side request forgery (SSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not limit URLs which may be used for the stock
  photo import feature, allowing the user to specify arbitrary URLs. This leads to a server-side
  request forgery as the user may force the server to access any URL of their choosing.");

  script_tag(name:"affected", value:"WordPress Orbit Fox by ThemeIsle prior to version 2.10.24.");

  script_tag(name:"solution", value:"Update to version 2.10.24 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/1b36a184-2138-4a65-8940-07e7764669bb");

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

if( version_is_less( version: version, test_version: "2.10.24" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.10.24", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
