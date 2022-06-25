###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xr_cisco-sa-20160519-ios-xr.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# Cisco IOS XR LPTS Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.105729");
  script_cve_id("CVE-2016-1407");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 11961 $");

  script_name("Cisco IOS XR LPTS Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160519-ios-xr");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the Local Packet Transport Services (LPTS) network stack of Cisco IOS XR for
Cisco ASR 9000 Series Aggregation Services Routers could allow an unauthenticated, remote attacker
to cause a limited denial of service (DoS) condition on an affected platform.


The vulnerability is due to improper handling of flow base entries by LPTS. This can cause too many
known entries for a protocol to be created, causing existing or new sessions to be dropped. An
attacker could exploit this vulnerability by sending continuous connection attempts to the open TCP
ports to cause an exhaustion of services. An exploit could allow the attacker to cause a limited DoS
condition on an affected platform.

Cisco has released software updates that address this vulnerability. Workarounds that address this
vulnerability are not available.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-23 14:24:54 +0200 (Mon, 23 May 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ios_xr_version.nasl");
  script_mandatory_keys("cisco/ios_xr/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );
if( ! model = get_kb_item( "cisco/ios_xr/model" ) ) exit( 0 );

if( "ASR9" >!< model ) exit( 99 );

affected = make_list(
		'2.0.0',
		'3.0.0',
		'3.0.1',
		'3.2.0',
		'3.2.1',
		'3.2.2',
		'3.2.3',
		'3.2.4',
		'3.2.50',
		'3.2.6',
		'3.3.0',
		'3.3.1',
		'3.3.2',
		'3.3.3',
		'3.3.4',
		'3.4.0',
		'3.4.1',
		'3.4.2',
		'3.4.3',
		'3.5.0',
		'3.5.2',
		'3.5.3',
		'3.5.4',
		'3.6',
		'3.6.1',
		'3.6.2',
		'3.6.3',
		'3.6.0',
		'3.7',
		'3.7.1',
		'3.7.2',
		'3.7.3',
		'3.7.0',
		'3.8.0',
		'3.8.1',
		'3.8.2',
		'3.8.3',
		'3.8.4',
		'3.9.0',
		'3.9.1',
		'3.9.2',
		'3.9.3',
		'4.0',
		'4.0.0',
		'4.0.1',
		'4.0.2',
		'4.0.3',
		'4.0.4',
		'4.0.11',
		'4.1',
		'4.1.0',
		'4.1.1',
		'4.1.2',
		'4.2.0',
		'4.2.1',
		'4.2.2',
		'4.2.3',
		'4.2.4',
		'4.3.0',
		'4.3.1',
		'4.3.2',
		'4.3.3',
		'4.3.4',
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
		'5.3.2',
		'5.0',
		'5.0.0',
		'5.0.1' );

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

