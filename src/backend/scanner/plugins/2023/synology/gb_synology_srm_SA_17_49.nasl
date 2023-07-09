# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:router_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170491");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-19 08:33:05 +0000 (Mon, 19 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-31 16:23:00 +0000 (Thu, 31 Aug 2017)");

  script_cve_id("CVE-2017-12077");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology Router Manager 1.1.x DoS Vulnerability (Synology-SA-17:49)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_synology_srm_consolidation.nasl");
  script_mandatory_keys("synology/srm/detected");

  script_tag(name:"summary", value:"Synology Router Manager (SRM) is prone to a denial of service
  (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is an uncontrolled resource consumption vulnerability in
  SYNO.Core.PortForwarding.Rules.");

  script_tag(name:"impact", value:"Successful exploitation allows remote authenticated attackers to
  exhaust the memory resources of the machine, causing a denial of service attack.");

  script_tag(name:"affected", value:"Synology Router Manager version 1.1.x prior to 1.1.4-6509.");

  script_tag(name:"solution", value:"Update to firmware version 1.1.4-6509 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_17_49_SRM");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if ( ( version =~ "^1\.1" ) && ( revcomp( a:version, b:"1.1.4-6509" ) < 0 ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.1.4-6509" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
