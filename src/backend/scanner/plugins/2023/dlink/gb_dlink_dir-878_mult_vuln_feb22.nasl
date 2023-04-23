# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:d-link:dir-878_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170422");
  script_version("2023-04-20T10:42:24+0000");
  script_tag(name:"last_modification", value:"2023-04-20 10:42:24 +0000 (Thu, 20 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-18 16:45:35 +0000 (Tue, 18 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-07 20:24:00 +0000 (Mon, 07 Feb 2022)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: 1.30B01_Beta_hotfix not detected

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2021-44880", "CVE-2021-44882");

  script_name("D-Link DIR-878 <= 1.30B08 Multiple Command Injection Vulnerabilities (Feb 2022)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-878 devices are prone to multiple command injection
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-44880: LAN-Side - command injection vulnerability in the system function via a crafted
  HNAP1 POST request.

  - CVE-2021-44882: LAN-Side - command injection vulnerability in the twsystem function via a crafted
  HNAP1 POST request.");

  script_tag(name:"affected", value:"D-Link DIR-878 devices through firmware version 1.30B08.");

  script_tag(name:"solution", value:"Update to firmware version 1.30B08_Beta_hotfix or later.");

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10286");
  script_xref(name:"URL", value:"https://support.dlink.com/productinfo.aspx?m=DIR-878");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

# nb: some of the versions might contain _Beta or other suffixes, using revcomp to be on the safe side
if ( revcomp( a:version, b:"1.30B08" ) <= 0 ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.30B08 Beta_Hotfix" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

