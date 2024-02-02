# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:backupbliss:backup_migration";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127671");
  script_version("2024-01-12T05:05:56+0000");
  script_tag(name:"last_modification", value:"2024-01-12 05:05:56 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"creation_date", value:"2023-12-29 10:10:45 +0000 (Fri, 29 Dec 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-29 06:21:00 +0000 (Fri, 29 Dec 2023)");

  script_cve_id("CVE-2023-6972", "CVE-2023-7002");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Backup Migration Plugin < 1.4.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/backup-backup/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Backup Migration' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-6972: Unauthenticated attackers are able to delete arbitrary files,
  including the wp-config.php file, which can make site takeover and remote code execution
  possible via the 'content-backups' and 'content-name', 'content-manifest', or 'content-bmitmp'
  and 'content-identy' HTTP headers.

  - CVE-2023-7002: Authenticated attackers, with administrator-level permissions and above are able
  to execute arbitrary commands on the host operating system via the 'url' parameter.");

  script_tag(name:"affected", value:"WordPress Backup Migration prior to version 1.4.0.");

  script_tag(name:"solution", value:"Update to version 1.4.0 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/0a3ae696-f67d-4ed2-b307-d2f36b6f188c");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/cc49db10-988d-42bd-a9cf-9a86f4c79568");

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

if( version_is_less( version: version, test_version: "1.4.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.4.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
