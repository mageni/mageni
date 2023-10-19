# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videousermanuals:white_label_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127291");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-01-03 08:30:16 +0000 (Tue, 03 Jan 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-09 19:52:00 +0000 (Mon, 09 Jan 2023)");

  script_cve_id("CVE-2022-4302");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress White Label CMS Plugin < 2.5 PHP Object Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/white-label-cms/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'White Label CMS' is prone to a
  PHP object injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin unserializes user input provided via the settings,
  which could allow to perform PHP Object Injection when a suitable gadget is present.");

  script_tag(name:"affected", value:"WordPress White Label CMS plugin prior to version 2.5.");

  script_tag(name:"solution", value:"Update to version 2.5 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/b7707a15-0987-4051-a8ac-7be2424bcb01");

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

if( version_is_less ( version: version, test_version: "2.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
