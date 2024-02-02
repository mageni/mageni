# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:updraftplus:updraftplus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127613");
  script_version("2023-11-17T16:10:13+0000");
  script_tag(name:"last_modification", value:"2023-11-17 16:10:13 +0000 (Fri, 17 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-08 12:22:41 +0000 (Wed, 08 Nov 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-15 15:37:00 +0000 (Wed, 15 Nov 2023)");

  script_cve_id("CVE-2023-5982");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress UpdraftPlus Plugin < 1.23.11 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/updraftplus/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'UpdraftPlus' is prone to a
  cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Attackers are able to modify the Google Drive location that
  backups are sent to via a forged request granted due to a lack of nonce validation and
  insufficient validation of the instance_id on the 'updraftmethod-googledrive-auth' action used to
  update Google Drive remote storage location.");

  script_tag(name:"affected", value:"WordPress UpdraftPlus prior to version 1.23.11.");

  script_tag(name:"solution", value:"Update to version 1.23.11 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/e1be11c5-0a44-4816-b6bf-d330cb51dbf3");

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

if( version_is_less( version: version, test_version: "1.23.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.23.11", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
