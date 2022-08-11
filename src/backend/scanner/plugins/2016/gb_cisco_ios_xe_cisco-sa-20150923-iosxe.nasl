###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xe_cisco-sa-20150923-iosxe.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# Cisco IOS XE Software Network Address Translation Denial of Service Vulnerability
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105680");
  script_cve_id("CVE-2015-6282");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 11961 $");

  script_name("Cisco IOS XE Software Network Address Translation Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150923-iosxe");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityBundle/cisco-sa-20150923-bundle");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=40939");
  script_xref(name:"URL", value:"http://www.cisco.com/web/about/security/intelligence/Cisco_ERP_sep15.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the processing of IPv4 packets that require
  Network Address Translation (NAT) and Multiprotocol Label Switching (MPLS) services of Cisco IOS
  XE Software for Cisco ASR 1000 Series, Cisco ISR 4300 Series, Cisco ISR 4400 Series, and Cisco Cloud
  Services 1000v Series Routers could allow an unauthenticated, remote attacker to cause a reload of the affected device.

  The vulnerability is due to improper processing of IPv4 packets that require NAT and MPLS processing.
  An attacker could exploit this vulnerability by sending an IPv4 packet to be processed by a Cisco IOS XE
  device configured to perform NAT and MPLS services. A successful exploit could allow the attacker to cause a reload of the affected device.

  Cisco has released software updates that address these vulnerabilities. There are no workarounds to mitigate this vulnerability.

  Note: The September 23, 2015, release of the Cisco IOS and IOS XE Software Security Advisory bundled publication
  includes three Cisco Security Advisories. All the advisories address vulnerabilities in Cisco IOS Software and
  Cisco IOS XE Software. Individual publication links are in Cisco Event Response: September 2015 Semiannual
  Cisco IOS and IOS XE Software Security Advisory Bundled Publication at the references.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-10 10:56:25 +0200 (Tue, 10 May 2016)");
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

if( ! model = get_kb_item("cisco_ios_xe/model") ) exit( 0 );

if( model !~ '^ASR1' && "ISR43" >!< model && "ISR44" >!< model && "1000V" >!< model ) exit( 99 );

affected = make_list(
		'2.1.0',
		'2.1.1',
		'2.1.2',
		'2.1.3',
		'2.2.1',
		'2.2.2',
		'2.2.3',
		'2.3.0',
		'2.3.0t',
		'2.3.1t',
		'2.3.2',
		'2.4.0',
		'2.4.1',
		'2.4.2',
		'2.4.3',
		'2.5.0',
		'2.5.1',
		'2.5.2',
		'2.6.0',
		'2.6.1',
		'2.6.2',
		'2.6.2a',
		'3.1.0S',
		'3.1.1S',
		'3.1.2S',
		'3.1.3S',
		'3.1.4S',
		'3.1.4S',
		'3.1.5S',
		'3.1.6S',
		'3.2.0S',
		'3.2.1S',
		'3.2.2S',
		'3.2.3S',
		'3.3.0S',
		'3.3.1S',
		'3.3.2S',
		'3.4.0S',
		'3.4.0S',
		'3.4.1S',
		'3.4.2S',
		'3.4.3S',
		'3.4.4S',
		'3.4.5S',
		'3.4.6S',
		'3.5.0S',
		'3.5.1S',
		'3.5.2S',
		'3.6.0S',
		'3.6.1S',
		'3.6.2S',
		'3.7.0S',
		'3.7.1S',
		'3.7.2S',
		'3.7.3S',
		'3.7.4S',
		'3.7.5S',
		'3.7.6S',
		'3.7.7S',
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
		'3.10.01S',
		'3.11.0S',
		'3.11.1S',
		'3.11.2S',
		'3.11.3S',
		'3.11.4S',
		'3.12.0S',
		'3.12.1S',
		'3.12.2S',
		'3.12.3S',
		'3.13.0S',
		'3.13.1S',
		'3.13.2S',
		'3.14.0S',
		'3.14.1S',
		'3.14.2S',
		'3.14.3S',
		'3.14.4S',
		'3.15.0S' );

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

