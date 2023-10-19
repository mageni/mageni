# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pagelayer:pagelayer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127527");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-22 07:38:12 +0000 (Tue, 22 Aug 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-08 16:48:00 +0000 (Fri, 08 Jan 2021)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-35944", "CVE-2020-35947");

  script_name("WordPress PageLayer Plugin < 1.1.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/pagelayer/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'PageLayer' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-35944: Attackers are able to forge a request on behalf of a site's administrator to
  modify the settings of the plugin which could allow for malicious Javascript injection.

  - CVE-2020-35947: Nearly all of the AJAX action endpoints in this plugin failed to include
  permission checks allowing these actions to be executed by anyone authenticated on the site.");

  script_tag(name:"affected", value:"WordPress PageLayer plugin prior to version 1.1.2.");

  script_tag(name:"solution", value:"Update to version 1.1.2 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/10240");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/10239");

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

if( version_is_less( version: version, test_version: "1.1.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.1.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
