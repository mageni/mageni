# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


CPE = "cpe:/a:piwigo:piwigo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124441");
  script_version("2023-10-17T05:05:34+0000");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-10 08:12:40 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-13 18:42:00 +0000 (Fri, 13 Oct 2023)");

  script_cve_id("CVE-2023-44393");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Piwigo < 14.0.0.beta4 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_piwigo_detect.nasl");
  script_mandatory_keys("piwigo/installed");

  script_tag(name:"summary", value:"Piwigo is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A stored cross-site scripting (XSS) in identification.php.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability by crafting a
  malicious URL that contains a specially crafted `plugin_id` value.");

  script_tag(name:"affected", value:"Piwigo prior to version 14.0.0.beta4.");

  script_tag(name:"solution", value:"Update to version 14.0.0.beta4 or later.");

  script_xref(name:"URL", value:"https://github.com/Piwigo/Piwigo/security/advisories/GHSA-qg85-957m-7vgg");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit(0);

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "14.0.0.beta4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "14.0.0.beta4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
