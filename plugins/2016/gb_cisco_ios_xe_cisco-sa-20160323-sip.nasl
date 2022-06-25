###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xe_cisco-sa-20160323-sip.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# Cisco IOS and IOS XE and Cisco Unified Communications Manager Software Session Initiation Protocol Memory Leak Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105660");
  script_cve_id("CVE-2016-1350");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12338 $");

  script_name("Cisco IOS and IOS XE and Cisco Unified Communications Manager Software Session Initiation Protocol Memory Leak Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-sip");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-51122");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityBundle/cisco-sa-20160323-bundle");


  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the Session Initiation Protocol (SIP) gateway implementation
  in Cisco IOS, IOS XE, and Cisco Unified Communications Manager Software could allow an unauthenticated,
  remote attacker to cause a memory leak and eventual reload of an affected device.

  The vulnerability is due to improper processing of malformed SIP messages. An attacker could exploit this vulnerability
  by sending malformed SIP messages to be processed by an affected device. An exploit could allow the attacker to cause
  a memory leak and eventual reload of the affected device.

  Cisco has released software updates that address this vulnerability. There are no workarounds that address
  this vulnerability other than disabling SIP on the vulnerable device.

  This advisory is part of the March 23, 2016, release of the Cisco IOS and IOS XE Software Security Advisory Bundled Publication,
  which includes six Cisco Security Advisories that describe six vulnerabilities. All the vulnerabilities have a Security Impact
  Rating of `High.` For a complete list of advisories and links to them, see Cisco Event Response:
  Semiannual Cisco IOS and IOS XE Software Security Advisory Bundled Publication.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-05-09 17:14:48 +0200 (Mon, 09 May 2016)");
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
		'3.8.0S',
		'3.8.1S',
		'3.8.2S',
		'3.9.0S',
		'3.9.0aS',
		'3.9.1S',
		'3.9.1aS',
		'3.9.2S',
		'3.10.0S',
		'3.10.1S',
		'3.10.1xbS',
		'3.10.2S',
		'3.11.0S' );

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

