# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:imagely:nextgen_gallery";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127591");
  script_version("2023-10-20T16:09:12+0000");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-18 12:10:39 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2023-3154", "CVE-2023-3155", "CVE-2023-3279");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress NextGEN Gallery Plugin < 3.39 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/nextgen-gallery/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'NextGen Gallery' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-3154: The plugin is vulnerable to PHAR Deserialization due to a lack of input
  parameter validation in the `gallery_edit` function, allowing an attacker to access arbitrary
  resources on the server.

  - CVE-2023-3155: The plugin is vulnerable to Arbitrary File Read and Delete due to a lack of
  input parameter validation in the `gallery_edit` function, allowing an attacker to access
  arbitrary resources on the server.

  - CVE-2023-3279: The plugin does not validate some block attributes before using them to generate
  paths passed to include function/s, allowing Admin users to perform LFI attacks.");

  script_tag(name:"affected", value:"WordPress NextGEN Gallery plugin prior to version 3.39.");

  script_tag(name:"solution", value:"Update to version 3.39 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/ed099489-1db4-4b42-9f72-77de39c9e01e/");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/5c8473f4-4b52-430b-9140-b81b0a0901da/");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/3b7a7070-8d61-4ff8-b003-b4ff06221635/");

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

if( version_is_less( version: version, test_version: "3.39" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.39", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
