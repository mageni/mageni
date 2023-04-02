# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/o:d-link:dir-867_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170361");
  script_version("2023-03-24T10:09:03+0000");
  script_tag(name:"last_modification", value:"2023-03-24 10:09:03 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-14 11:22:36 +0000 (Tue, 14 Mar 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2023-24762");

  script_name("D-Link DIR-867 <= v1.30B07 Command Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-867 devices are prone to acommand injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A command injection vulnerability in the component LocalIPAddress
  allows attackers to escalate privileges to root via a crafted payload.");

  script_tag(name:"affected", value:"D-Link DIR-867 devices through firmware version 1.30B07.");

  script_tag(name:"solution", value:"No known solution is available as of 14th March, 2023.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://support.dlink.com/ProductInfo.aspx?m=DIR-867-US");
  script_xref(name:"URL", value:"https://hackmd.io/@uuXne2y3RjOdpWM87fw6_A/HyPK04zho");
  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

# nb: some of the versions might contain _Beta or other suffixes, using revcomp to be on the safe side
if ( revcomp( a:version, b:"1.30B07" ) <= 0 ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"None" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 0 );
