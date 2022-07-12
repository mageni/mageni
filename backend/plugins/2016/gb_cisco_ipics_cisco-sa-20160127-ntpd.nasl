###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ipics_cisco-sa-20160127-ntpd.nasl 11922 2018-10-16 10:24:25Z asteins $
#
# Multiple Vulnerabilities in Network Time Protocol Daemon Affecting Cisco Products: January 2016
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

CPE = "cpe:/a:cisco:ip_interoperability_and_collaboration_system";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105726");
  script_cve_id("CVE-2015-7974", "CVE-2015-7975", "CVE-2015-7976", "CVE-2015-7978", "CVE-2015-7977", "CVE-2015-7979", "CVE-2015-8138", "CVE-2015-8139", "CVE-2015-8140", "CVE-2015-8158", "CVE-2015-7973");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_version("$Revision: 11922 $");

  script_name("Multiple Vulnerabilities in Network Time Protocol Daemon Affecting Cisco Products: January 2016");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160127-ntpd");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"Multiple Cisco products incorporate a version of the Network Time Protocol daemon (ntpd) package.
  Versions of this package are affected by one or more vulnerabilities that could allow an
  unauthenticated, remote attacker to create a denial of service (DoS) condition or modify the time
  being advertised by a device acting as a Network Time Protocol (NTP) server.

  On January 19, 2016, NTP Consortium at Network Time Foundation released a security advisory
  detailing 12 issues regarding multiple DoS vulnerabilities, information disclosure vulnerabilities,
  and logic issues that may allow an attacker to shift a client's time. The vulnerabilities covered in
  this document are as follows: CVE-2015-7973: Network Time Protocol Replay Attack on Authenticated
  Broadcast Mode Vulnerability CVE-2015-7974: Network Time Protocol Missing Trusted Key Check CVE-2015-
  7975: Standard Network Time Protocol Query Program nextvar() Missing Length Check CVE-2015-7976:
  Standard Network Time Protocol Query Program saveconfig Command Allows Dangerous Characters in
  Filenames CVE-2015-7978: Network Time Protocol Daemon reslist NULL Pointer Deference Denial of
  Service Vulnerability CVE-2015-7977: Network Time Protocol Stack Exhaustion Denial of Service CVE-2015-
  7979: Network Time Protocol Off-Path Broadcast Mode Denial of Service CVE-2015-8138: Network Time
  Protocol Zero Origin Timestamp Bypass CVE-2015-8139: Network Time Protocol Information Disclosure of
  Origin Timestamp CVE-2015-8140: Standard Network Time Protocol Query Program Replay Attack CVE-2015-
  8158: Standard and Special Network Time Protocol Query Program Infinite loop

  Cisco has released software updates that address these vulnerabilities.

  Workarounds that address some of these vulnerabilities may be available. Available workarounds will
  be documented in the corresponding Cisco bug for each affected product.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-16 12:24:25 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-18 10:53:18 +0200 (Wed, 18 May 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ipics_version.nasl");
  script_mandatory_keys("cisco/ipics/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
		'1.0(1.1)',
		'4.0(1)',
		'4.5(1)',
		'4.6(1)',
		'4.7(1)',
		'4.8(2)' );

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

