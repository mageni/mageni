# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:d-link:dir-819_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170420");
  script_version("2023-04-20T10:42:24+0000");
  script_tag(name:"last_modification", value:"2023-04-20 10:42:24 +0000 (Thu, 20 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-18 08:36:13 +0000 (Tue, 18 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2022-40946");

  script_name("D-Link DIR-819 Rev. A <= v1.06b06Beta DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected", "d-link/dir/hw_version");

  script_tag(name:"summary", value:"D-Link DIR-819 Rev. A devices are prone to a denial of service
  (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It is possible to trigger a Denial of Service via the sys_token
  parameter in a cgi-bin/webproc?getpage=html/index.html request.");

  script_tag(name:"affected", value:"D-Link DIR-819 Rev. A devices through firmware version
  1.06b06Beta.");

  script_tag(name:"solution", value:"No known solution is available as of 18th April, 2023.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://support.dlink.ca/ProductInfo.aspx?m=DIR-819");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/171484/D-Link-DIR-819-A1-Denial-Of-Service.html");
  script_xref(name:"URL", value:"https://github.com/whokilleddb/dlink-dir-819-dos");
  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

hw_version = get_kb_item( "d-link/dir/hw_version" );
if ( ! hw_version )
  exit( 0 );

# nb: some of the versions might contain _Beta or other suffixes, using revcomp to be on the safe side
if ( ( hw_version =~ "A" ) && ( revcomp( a:version, b:"1.06B06Beta" ) <= 0 ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"None", extra:"Hardware revision: " + hw_version );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 0 );
