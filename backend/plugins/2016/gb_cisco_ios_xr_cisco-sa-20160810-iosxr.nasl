###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xr_cisco-sa-20160810-iosxr.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# Cisco IOS XR Software for Cisco ASR 9001 Aggregation Services Routers Fragmented Packet Denial of Service Vulnerability
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

CPE = "cpe:/o:cisco:ios_xr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106177");
  script_cve_id("CVE-2016-6355");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12051 $");

  script_name("Cisco IOS XR Software for Cisco ASR 9001 Aggregation Services Routers Fragmented Packet Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160810-iosxr");


  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the driver processing functions of Cisco IOS XR
Software for Cisco ASR 9001 Aggregation Services Routers could allow an unauthenticated, remote attacker to
cause a memory leak on the route processor (RP) of an affected device, which could cause the device to drop
all control-plane protocols and lead to a denial of service condition (DoS) on a targeted system.

The vulnerability is due to improper handling of crafted, fragmented packets that are directed to an
affected device. An attacker could exploit this vulnerability by sending crafted, fragmented packets
to an affected device for processing and reassembly. A successful exploit could allow the attacker
to cause a memory leak on the RP of the device, which could cause the device to drop all control-
plane protocols and eventually lead to a DoS condition on the targeted system.

Cisco has released software updates that address this vulnerability. There are no workarounds that
address this vulnerability. However, there are mitigations for this vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-16 08:52:29 +0700 (Tue, 16 Aug 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ios_xr_version.nasl");
  script_mandatory_keys("cisco/ios_xr/version", "cisco/ios_xr/model", "cisco_ios_xr/ssh/chassis");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!model = get_kb_item("cisco/ios_xr/model"))
  exit(0);

if ("ASR9K" >!< model)
  exit(0);

if (!chassis = get_kb_item("cisco_ios_xr/ssh/chassis"))
  exit(0);

if ("ASR-9001" >!< chassis)
  exit(0);

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
		'5.1.0',
		'5.1.1',
		'5.1.2',
		'5.1.1.K9SEC',
		'5.1.3',
		'5.2.0',
		'5.2.1',
		'5.2.2',
		'5.2.4',
		'5.2.3',
		'5.2.5',
		'5.3.0',
		'5.3.1',
		'5.3.2' );

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

