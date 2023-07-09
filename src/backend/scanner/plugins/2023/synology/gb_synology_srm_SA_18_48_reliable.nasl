# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:router_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170495");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-19 08:33:05 +0000 (Mon, 19 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:34:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2018-13289", "CVE-2018-13290", "CVE-2018-13292");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology Router Manager 1.1.x Multiple Vulnerabilities (Synology-SA-18:48) - Remote Known Vulnerable Versions Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_synology_srm_consolidation.nasl");
  script_mandatory_keys("synology/srm/detected");

  script_tag(name:"summary", value:"Synology Router Manager (SRM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2018-13289: Information exposure vulnerability in SYNO.FolderSharing.List allows remote
  attackers to obtain sensitive information via the (1) folder_path or (2) real_path parameter.

  - CVE-2018-13290: Information exposure vulnerability in SYNO.Core.ACL allows remote authenticated
  users to determine the existence of files or obtain sensitive information of files via the file_path
  parameter.

  - CVE-2018-13292: Information exposure vulnerability in /usr/syno/etc/mount.conf allows remote
  authenticated users to obtain sensitive information via the world readable configuration.");

  script_tag(name:"affected", value:"Synology Router Manager version 1.1.x prior to 1.1.7-6941-2.");

  script_tag(name:"solution", value:"Update to firmware version 1.1.7-6941-2 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_18_48");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

# nb: The patch level version cannot be obtained so when the fix is on a patch level version,
# there will be 2 VTs with different qod_type.
if ( ( version =~ "^1\.1" ) && ( revcomp( a:version, b:"1.1.7-6941" ) < 0 ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.1.7-6941-2" );
  security_message( port:0, data:report );
  exit( 0 );
}

# nb: This is checked by VT 1.3.6.1.4.1.25623.1.0.170496
if ( version =~ "^1\.1\.7-6941" )
  exit( 0 );

exit( 99 );
