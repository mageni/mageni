# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:backupbliss:backup_migration";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127670");
  script_version("2024-01-12T05:05:56+0000");
  script_tag(name:"last_modification", value:"2024-01-12 05:05:56 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"creation_date", value:"2023-12-29 09:10:45 +0000 (Fri, 29 Dec 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-29 06:21:00 +0000 (Fri, 29 Dec 2023)");

  script_cve_id("CVE-2023-6971");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Backup Migration Plugin 1.0.8 < 1.4.0 Remote File Inclusion Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/backup-backup/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Backup Migration' is prone to a remote
  file inclusion vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Unauthenticated attackers are able to include remote files on
  the server, resulting in code execution.");

  script_tag(name:"insight", value:"Successful exploitation of this vulnerability requires that the
  target server's php.ini is configured with 'allow_url_include' set to 'on'.");

  script_tag(name:"affected", value:"WordPress Backup Migration version 1.0.8 prior to 1.4.0.");

  script_tag(name:"solution", value:"Update to version 1.4.0 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/b380283c-0dbb-4d67-9f66-cb7c400c0427");

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

if( version_in_range_exclusive( version: version, test_version_lo: "1.0.8", test_version_up: "1.4.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.4.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
