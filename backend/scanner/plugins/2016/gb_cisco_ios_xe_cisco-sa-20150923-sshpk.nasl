###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xe_cisco-sa-20150923-sshpk.nasl 11922 2018-10-16 10:24:25Z asteins $
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

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105674");
  script_cve_id("CVE-2015-6280");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11922 $");

  script_name("Cisco IOS and IOS XE Software SSH Version 2 RSA-Based User Authentication Bypass Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150923-sshpk");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityBundle/cisco-sa-20150923-bundle");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=40938");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityBundle/cisco-sa-20150923-bundle");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=40938");
  script_xref(name:"URL", value:"http://www.cisco.com/web/about/security/intelligence/Cisco_ERP_sep15.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the SSH version 2 (SSHv2) protocol implementation
  of Cisco IOS and IOS XE Software could allow an unauthenticated, remote attacker to bypass user authentication.

  Successful exploitation could allow the attacker to log in with the privileges of the user or the privileges
  configured for the Virtual Teletype (VTY) line. Depending on the configuration of the user and of the vty line,
  the attacker may obtain administrative privileges on the system. The attacker cannot use this vulnerability to elevate privileges.

  The attacker must know a valid username configured for Rivest, Shamir, and Adleman (RSA)-based user authentication
  and the public key configured for that user to exploit this vulnerability. This vulnerability
  affects only devices configured for public key authentication method, also known as an RSA-based user authentication feature.


  Cisco has released software updates that address this vulnerability. Workarounds for this vulnerability are not available,
  however administrators could temporarily disable RSA-based user authentication to avoid exploitation. This advisory is available at the references.


  Note: The September 23, 2015, release of the Cisco IOS and IOS XE Software Security Advisory bundled publication includes three Cisco Security Advisories.
  All the advisories address vulnerabilities in Cisco IOS Software and Cisco IOS XE Software. Individual publication links are in Cisco Event Response:
  September 2015 Semiannual Cisco IOS and IOS XE Software Security Advisory Bundled Publication at the references.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-16 12:24:25 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-10 10:45:39 +0200 (Tue, 10 May 2016)");
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
		'3.6.0E',
		'3.6.0E',
		'3.6.0E',
		'3.6.1E',
		'3.6.2E',
		'3.6.2E',
		'3.7.0E',
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
		'3.12.0S',
		'3.12.1S',
		'3.12.2S',
		'3.13.0S',
		'3.13.1S',
		'3.13.2S',
		'3.14.0S' );

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

