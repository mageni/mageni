###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xe_cisco-sa-20161012-cbr-8.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# Cisco cBR-8 Converged Broadband Router vty Integrity Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106357");
  script_cve_id("CVE-2016-6438");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 12431 $");

  script_name("Cisco cBR-8 Converged Broadband Router vty Integrity Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161012-cbr-8");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in Cisco IOS XE Software running on Cisco cBR-8 Converged
Broadband Routers could allow an unauthenticated, remote attacker to cause a configuration integrity change to
the vty line configuration on an affected device.");

  script_tag(name:"insight", value:"The vulnerability is due to a logic processing error that exists if an
affected device is configured with the Downstream Resiliency and Downstream Resiliency Bonding Group features. An
attacker could exploit this vulnerability by continuously trying to establish Telnet or SSH connections to a
targeted device.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-14 14:01:45 +0700 (Fri, 14 Oct 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ios_xe_version.nasl");
  script_mandatory_keys("cisco_ios_xe/version", "cisco_ios_xe/model");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

model = get_kb_item("cisco_ios_xe/model");
if (!model || model !~ "^cBR")
  exit(99);

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
		'3.18.0S',
		'3.18.1S',
		'3.18.0SP',
		'3.17.1aS',
		'3.17.0S',
		'3.17.2S',
		'3.17.1S',
		'3.16.2bS',
		'3.16.3aS',
		'3.16.3S',
		'3.16.4S',
		'3.16.0S',
		'3.16.0cS',
		'3.16.1S',
		'3.16.1aS',
		'3.16.2S',
		'3.16.2aS' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

