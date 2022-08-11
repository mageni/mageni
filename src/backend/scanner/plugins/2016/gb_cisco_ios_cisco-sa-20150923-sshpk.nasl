###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_cisco-sa-20150923-sshpk.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# Cisco IOS and IOS XE Software SSH Version 2 RSA-Based User Authentication Bypass Vulnerability
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

CPE = "cpe:/o:cisco:ios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105640");
  script_cve_id("CVE-2015-6280");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12313 $");

  script_name("Cisco IOS and IOS XE Software SSH Version 2 RSA-Based User Authentication Bypass Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150923-sshpk");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityBundle/cisco-sa-20150923-bundle");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=40938");
  script_xref(name:"URL", value:"http://www.cisco.com/web/about/security/intelligence/Cisco_ERP_sep15.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the SSH version 2 (SSHv2) protocol implementation of Cisco IOS and IOS XE Software could allow an
  unauthenticated, remote attacker to bypass user authentication.

  Successful exploitation could allow the attacker to log in with the privileges of the user or the privileges
  configured for the Virtual Teletype (VTY) line. Depending on the configuration of the user and of the vty line,
  the attacker may obtain administrative privileges on the system. The attacker cannot use this vulnerability to elevate privileges.

  The attacker must know a valid username configured for Rivest, Shamir, and Adleman (RSA)-based user authentication
  and the public key configured for that user to exploit this vulnerability. This vulnerability
  affects only devices configured for public key authentication method, also known as an RSA-based user authentication feature.

  Cisco has released software updates that address this vulnerability. Workarounds for this vulnerability are not available.
  However administrators could temporarily disable RSA-based user authentication to avoid exploitation. This advisory is available via the references.

  Note: The September 23, 2015, release of the Cisco IOS and IOS XE Software Security Advisory bundled publication includes three Cisco Security Advisories.
  All the advisories address vulnerabilities in Cisco IOS Software and Cisco IOS XE Software. Individual publication links are in Cisco Event Response:
  September 2015 Semiannual Cisco IOS and IOS XE Software Security Advisory Bundled Publication at the references.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-05-03 19:31:26 +0200 (Tue, 03 May 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_ssh_cisco_ios_get_version.nasl");
  script_mandatory_keys("cisco_ios/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
		'15.2(2)E',
		'15.2(2)E1',
		'15.2(2)E2',
		'15.2(2a)E1',
		'15.2(2a)E2',
		'15.2(3)E',
		'15.2(3a)E',
		'15.2(2)EA1',
		'15.2(3)EA',
		'15.2(1)SY',
		'15.2(1)SY0a',
		'15.3(3)M1',
		'15.3(3)M2',
		'15.3(3)M3',
		'15.3(3)M4',
		'15.3(3)M5',
		'15.3(3)S',
		'15.3(3)S1',
		'15.3(3)S1a',
		'15.3(3)S2',
		'15.3(3)S3',
		'15.3(3)S4',
		'15.3(3)S5',
		'15.4(1)CG',
		'15.4(1)CG1',
		'15.4(2)CG',
		'15.4(3)M',
		'15.4(3)M1',
		'15.4(3)M2',
		'15.4(1)S',
		'15.4(1)S1',
		'15.4(1)S2',
		'15.4(1)S3',
		'15.4(2)S',
		'15.4(2)S1',
		'15.4(2)S2',
		'15.4(3)S',
		'15.4(3)S1',
		'15.4(3)S2',
		'15.4(1)T',
		'15.4(1)T1',
		'15.4(1)T2',
		'15.4(1)T3',
		'15.4(2)T',
		'15.4(2)T1',
		'15.4(2)T2',
		'15.5(1)S',
		'15.5(1)T' );

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

