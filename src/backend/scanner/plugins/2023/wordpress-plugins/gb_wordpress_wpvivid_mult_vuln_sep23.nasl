# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpvivid:migration%2c_backup%2c_staging";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127601");
  script_version("2023-10-31T05:06:37+0000");
  script_tag(name:"last_modification", value:"2023-10-31 05:06:37 +0000 (Tue, 31 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-26 11:05:08 +0000 (Thu, 26 Oct 2023)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-27 17:46:00 +0000 (Fri, 27 Oct 2023)");

  script_cve_id("CVE-2023-4274", "CVE-2023-5120", "CVE-2023-5121");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Migration, Backup, Staging - WPvivid Plugin < 0.9.90 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wpvivid-backuprestore/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Migration, Backup, Staging - WPvivid' is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-4274: Attackers are able to delete the contents of arbitrary directories on the
  server, which can be a critical issue in a shared environments.

  - CVE-2023-5120: Attackers are able to inject arbitrary web scripts in pages due to insufficient
  image file path parameter sanitization.

  - CVE-2023-5121: Attackers are able to inject arbitrary web scripts in pages due to insufficient
  backup path parameter sanitization.");

  script_tag(name:"affected", value:"WordPress Migration, Backup, Staging - WPvivid plugin prior to
  version 0.9.90.");

  script_tag(name:"solution", value:"Update to version 0.9.90 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/5d94f38f-4b52-4b0d-800c-a6fca40bda3c");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/320f4260-20c2-4f27-91ba-d2488b417f62");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/cdcac5f9-a744-4853-8a80-ed38fec81dbb");

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

if( version_is_less( version: version, test_version: "0.9.90" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "0.9.90", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
