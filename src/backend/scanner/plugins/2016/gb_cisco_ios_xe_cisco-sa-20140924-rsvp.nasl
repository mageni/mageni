###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xe_cisco-sa-20140924-rsvp.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# Cisco IOS Software RSVP Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105685");
  script_cve_id("CVE-2014-3354");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12051 $");

  script_name("Cisco IOS Software RSVP Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-rsvp");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityBundle/cisco-sa-20140924-bundle");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=35621");
  script_xref(name:"URL", value:"http://www.cisco.com/web/about/security/intelligence/Cisco_ERP_sep14.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the implementation of the Resource Reservation Protocol
  (RSVP) in Cisco IOS Software and Cisco IOS XE Software could allow an unauthenticated, remote attacker cause
  the device to reload. This vulnerability could be exploited repeatedly to cause an extended denial of service (DoS) condition.

  Cisco has released software updates that address this vulnerability.

  A workaround that mitigates this vulnerability is available.

  Note: The September 24, 2014, Cisco IOS Software Security Advisory bundled publication includes six Cisco Security Advisories.
  All advisories address vulnerabilities in Cisco IOS Software. Individual publication links are in Cisco Event Response:
  Semiannual Cisco IOS Software Security Advisory Bundled Publication at the referenced links.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-10 11:06:48 +0200 (Tue, 10 May 2016)");
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
		'2.1.0',
		'2.1.1',
		'2.1.2',
		'2.2.1',
		'2.2.2',
		'2.2.3',
		'2.3.0',
		'2.3.0t',
		'2.3.1t',
		'2.3.2',
		'2.4.0',
		'2.4.1',
		'2.5.0',
		'2.6.0',
		'2.6.1',
		'2.6.2',
		'3.1.0S',
		'3.1.1S',
		'3.1.2S',
		'3.1.3S',
		'3.2.0S',
		'3.2.1S',
		'3.2.2S',
		'3.2.0SE',
		'3.2.1SE',
		'3.3.0S',
		'3.3.1S',
		'3.3.2S',
		'3.3.0SE',
		'3.3.1SE',
		'3.3.0SG',
		'3.3.1SG',
		'3.3.2SG',
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
		'3.8.0S',
		'3.8.1S',
		'3.8.2S',
		'3.9.0S',
		'3.9.1S',
		'3.10.0S' );

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

