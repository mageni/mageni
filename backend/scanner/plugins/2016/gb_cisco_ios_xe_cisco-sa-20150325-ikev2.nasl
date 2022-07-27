###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xe_cisco-sa-20150325-ikev2.nasl 12449 2018-11-21 07:50:18Z cfischer $
#
# Cisco IOS Software and IOS XE Software Internet Key Exchange Version 2 Denial of Service Vulnerabilities
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

CPE = "cpe:/o:cisco:ios_xe";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105672");
  script_cve_id("CVE-2015-0643", "CVE-2015-0642");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12449 $");

  script_name("Cisco IOS Software and IOS XE Software Internet Key Exchange Version 2 Denial of Service Vulnerabilities");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-ikev2");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=37815");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=37816");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=43609");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityBundle/cisco-sa-20150325-bundle");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"Devices running Cisco IOS Software or IOS XE Software contain vulnerabilities within
  the Internet Key Exchange (IKE) version 2 subsystem that could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition.

  The vulnerabilities are due to how an affected device processes certain malformed IKEv2 packets. An attacker could exploit these vulnerabilities
  by sending malformed IKEv2 packets to an affected device to be processed. A successful exploit could allow the attacker to cause a reload of the
  affected device or excessive consumption of resources that would lead to a DoS condition. IKEv2 is automatically enabled on devices running Cisco
  IOS and Cisco IOS XE Software when the Internet Security Association and Key Management Protocol (ISAKMP) is enabled. These vulnerabilities can only be triggered by sending malformed IKEv2 packets.

  There are no workarounds for the vulnerabilities described in this advisory. Cisco has released software updates that address these vulnerabilities.

  Note: The March 25, 2015, Cisco IOS & XE Software Security Advisory bundled publication includes seven Cisco Security Advisories.
  The advisories address vulnerabilities in Cisco IOS Software and Cisco IOS XE Software. Individual publication links are in Cisco Event Response:
  Semiannual Cisco IOS & XE Software Security Advisory Bundled Publication at the referenced link");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-21 08:50:18 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-05-10 10:42:54 +0200 (Tue, 10 May 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ios_xe_version.nasl");
  script_mandatory_keys("cisco_ios_xe/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
		'2.5.0',
		'2.5.1',
		'3.1.0S',
		'3.1.1S',
		'3.1.2S',
		'3.1.3S',
		'3.1.4S',
		'3.2.0S',
		'3.2.1S',
		'3.2.2S',
		'3.3.0S',
		'3.3.1S',
		'3.3.2S',
		'3.3.0SG',
		'3.3.1SG',
		'3.3.2SG',
		'3.3.0XO',
		'3.3.1XO',
		'3.3.2XO',
		'3.4.0S',
		'3.4.1S',
		'3.4.2S',
		'3.4.3S',
		'3.4.4S',
		'3.4.5S',
		'3.4.6S',
		'3.4.0SG',
		'3.4.1SG',
		'3.4.2SG',
		'3.4.3SG',
		'3.4.4SG',
		'3.4.5SG',
		'3.5.0E',
		'3.5.1E',
		'3.5.2E',
		'3.5.3E',
		'3.5.0S',
		'3.5.1S',
		'3.5.2S',
		'3.6.0E',
		'3.6.1E',
		'3.6.0S',
		'3.6.1S',
		'3.6.2S',
		'3.7.0E',
		'3.7.0S',
		'3.7.1S',
		'3.7.2S',
		'3.7.3S',
		'3.7.4S',
		'3.7.5S',
		'3.7.6S',
		'3.8.0S',
		'3.8.1S',
		'3.8.2S',
		'3.9.0S',
		'3.9.1S',
		'3.9.2S',
		'3.10.0S',
		'3.10.0S',
		'3.10.1S',
		'3.10.2S',
		'3.10.3S',
		'3.10.4S',
		'3.10.5S',
		'3.11.0S',
		'3.11.1S',
		'3.11.2S',
		'3.11.3S',
		'3.12.0S',
		'3.12.1S',
		'3.12.2S',
		'3.13.0S',
		'3.13.1S' );

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

