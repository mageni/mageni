# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:code-atlantic:popup_maker";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170319");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-02-23 17:28:06 +0000 (Thu, 23 Feb 2023)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-23 15:58:00 +0000 (Wed, 23 Nov 2022)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2022-3690");

  script_name("WordPress Popup Maker Plugin < 1.16.11 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/popup-maker/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Popup Maker' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not sanitise and escape some of its Popup options,
  which could allow users with a role as low as Contributor to perform stored cross-site scripting
  attacks, which could be used against admins.");

  script_tag(name:"affected", value:"WordPress Popup Maker plugin prior to version 1.16.11.");

  script_tag(name:"solution", value:"Update to version 1.16.11 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/725f6ae4-7ec5-4d7c-9533-c9b61b59cc2b");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"1.16.11" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.16.11", install_path:location );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
