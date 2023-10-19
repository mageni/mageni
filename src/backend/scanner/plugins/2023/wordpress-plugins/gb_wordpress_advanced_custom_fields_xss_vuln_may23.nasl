# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only
CPE = "cpe:/a:advancedcustomfields:advanced_custom_fields";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126292");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-05-08 10:11:11 +0000 (Mon, 08 May 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-17 16:42:00 +0000 (Wed, 17 May 2023)");

  script_cve_id("CVE-2023-30777");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Advanced Custom Fields Plugin < 6.1.6 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/advanced-custom-fields/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Advanced Custom Fields' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin allows any unauthenticated user to steal sensitive
  information. In this case, by tricking privileged user to visit the crafted URL path.");

  script_tag(name:"affected", value:"WordPress Advanced Custom Fields prior to version 6.1.6.");

  script_tag(name:"solution", value:"Update to version 6.1.6 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/articles/reflected-xss-in-advanced-custom-fields-plugins-affecting-2-million-sites/");

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

if (version_is_less(version: version, test_version: "6.1.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit( 99 );
