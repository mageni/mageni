# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:diskstation_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170617");
  script_version("2023-10-24T14:40:27+0000");
  script_tag(name:"last_modification", value:"2023-10-24 14:40:27 +0000 (Tue, 24 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-23 20:02:15 +0000 (Mon, 23 Oct 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2015-2809");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology DiskStation Manager < 3.1 Information Disclosure Vulnerability (Feb 2015)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/detected");

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Multicast DNS (mDNS) responder inadvertently responds to
  unicast queries with source addresses that are not link-local, which allows remote attackers to
  cause a denial of service (traffic amplification) or obtain potentially sensitive information via
  port-5353 UDP packets to the Avahi component.");

  script_tag(name:"affected", value:"Synology DiskStation Manager prior to version 3.1.");

  script_tag(name:"solution", value:"Update to firmware version 3.1 or later.");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/550620");
  script_xref(name:"URL", value:"https://web.archive.org/web/20200228091429/http://www.securityfocus.com/bid/73683");


  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if ( revcomp( a:version, b:"3.1" ) < 0 ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.1" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
