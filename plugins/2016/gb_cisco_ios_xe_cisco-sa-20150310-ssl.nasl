###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xe_cisco-sa-20150310-ssl.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# Multiple Vulnerabilities in OpenSSL (January 2015) Affecting Cisco Products
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
  script_oid("1.3.6.1.4.1.25623.1.0.105679");
  script_cve_id("CVE-2014-3571", "CVE-2015-0206", "CVE-2014-3569", "CVE-2014-3572", "CVE-2015-0204", "CVE-2015-0205", "CVE-2014-8275", "CVE-2014-3570");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 11961 $");

  script_name("Multiple Vulnerabilities in OpenSSL (January 2015) Affecting Cisco Products");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150310-ssl");


  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"Multiple Cisco products incorporate a version of the OpenSSL package
  affected by one or more vulnerabilities that could allow an unauthenticated, remote attacker to cause
  a denial of service condition or perform a man-in-the-middle attack. On January 8, 2015, the OpenSSL Project
  released a security advisory detailing eight distinct vulnerabilities. The vulnerabilities are referenced in this document as follows:

  - CVE-2014-3571: OpenSSL DTLS Message Processing Denial of Service Vulnerability

  - CVE-2015-0206: OpenSSL dtls1_buffer_record Function DTLS Message Processing Denial of Service Vulnerability

  - CVE-2014-3569: OpenSSL no-ssl3 Option NULL Pointer Dereference Vulnerability

  - CVE-2014-3572: OpenSSL Elliptic Curve Cryptographic Downgrade Vulnerability

  - CVE-2015-0204: OpenSSL RSA Temporary Key Cryptographic Downgrade Vulnerability

  - CVE-2015-0205: OpenSSL Diffie-Hellman Certificate Validation Authentication Bypass Vulnerability

  - CVE-2014-8275: OpenSSL Certificate Fingerprint Validation Vulnerability

  - CVE-2014-3570: OpenSSL BN_sql Function Incorrect Mathematical Results Issue

  Cisco will release software updates that address these vulnerabilities.

  Workarounds that mitigate these vulnerabilities may be available.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-10 10:55:20 +0200 (Tue, 10 May 2016)");
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
		'3.3.0S',
		'3.3.1S',
		'3.3.2S',
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
		'3.8.0S',
		'3.8.1S',
		'3.8.2S',
		'3.9.0S',
		'3.9.1S',
		'3.9.2S' );

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

