# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpmanageninja:fluentsmtp";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124297");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-03-27 08:29:25 +0000 (Mon, 27 Mar 2023)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-02 15:21:00 +0000 (Thu, 02 Sep 2021)");

  script_cve_id("CVE-2021-24528");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress FluentSMTP Plugin < 2.0.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/fluent-smtp/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'FluentSMTP' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not sanitize parameters before storing the
  settings in the database, nor does the plugin escape the values before outputting them when
  viewing the SMTP settings set by this plugin, leading to a stored cross site scripting (XSS)
  vulnerability. Only users with roles capable of managing plugins can modify the plugin's settings.");

  script_tag(name:"affected", value:"WordPress FluentSMTP plugin prior to version 2.0.1.");

  script_tag(name:"solution", value:"Update to version 2.0.1 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/8b8d316b-96b2-4cdc-9da5-c9ea6108a85b");

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

if( version_is_less( version:version, test_version:"2.0.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.0.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
