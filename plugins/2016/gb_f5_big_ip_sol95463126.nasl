###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_f5_big_ip_sol95463126.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# F5 BIG-IP - SOL95463126 - OpenSSL vulnerabilities CVE-2016-0703 and CVE-2016-0704
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

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105567");
  script_cve_id("CVE-2016-0703", "CVE-2016-0704", "CVE-2016-0800");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 12431 $");

  script_name("F5 BIG-IP - SOL95463126 - OpenSSL vulnerabilities CVE-2016-0703 and CVE-2016-0704");

  script_xref(name:"URL", value:"https://support.f5.com/kb/en-us/solutions/public/k/95/sol95463126.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The get_client_master_key function in s2_srvr.c in the SSLv2 implementation in OpenSSL before 0.9.8zf, 1.0.0 before 1.0.0r, 1.0.1 before 1.0.1m, and 1.0.2 before 1.0.2a accepts a nonzero CLIENT-MASTER-KEY CLEAR-KEY-LENGTH value for an arbitrary cipher, which allows man-in-the-middle attackers to determine the MASTER-KEY value and decrypt TLS ciphertext data by leveraging a Bleichenbacher RSA padding oracle, a related issue to CVE-2016-0800. An oracle protection mechanism in the get_client_master_key function in s2_srvr.c in the SSLv2 implementation in OpenSSL before 0.9.8zf, 1.0.0 before 1.0.0r, 1.0.1 before 1.0.1m, and 1.0.2 before 1.0.2a overwrites incorrect MASTER-KEY bytes during use of export cipher suites, which makes it easier for remote attackers to decrypt TLS ciphertext data by leveraging a Bleichenbacher RSA padding oracle, a related issue to CVE-2016-0800.");
  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"The remote host is missing a security patch.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-03-15 12:34:21 +0100 (Tue, 15 Mar 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("F5 Local Security Checks");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_f5_big_ip_version.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("f5/big_ip/version", "f5/big_ip/active_modules");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("f5.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

check_f5['LTM'] = make_array( 'affected',   '11.6.0-11.6.0_HF4;11.5.0-11.5.3_HF1;11.3.0-11.4.1_HF8;11.0.0-11.2.1_HF14;10.1.0-10.2.4;',
                              'unaffected', '12.0.0;11.6.1;11.6.0_HF5;11.5.4;11.5.3_HF2;11.4.1_HF9;11.2.1_HF15;');

check_f5['AAM'] = make_array( 'affected',   '11.6.0-11.6.0_HF4;11.5.0-11.5.3_HF1;11.4.0-11.4.1_HF8;',
                              'unaffected', '12.0.0;11.6.1;11.6.0_HF5;11.5.4;11.5.3_HF2;11.4.1_HF9;');

check_f5['AFM'] = make_array( 'affected',   '11.6.0-11.6.0_HF4;11.5.0-11.5.3_HF1;11.3.0-11.4.1_HF8;',
                              'unaffected', '12.0.0;11.6.1;11.6.0_HF5;11.5.4;11.5.3_HF2;11.4.1_HF9;');

check_f5['AVR'] = make_array( 'affected',   '11.6.0-11.6.0_HF4;11.5.0-11.5.3_HF1;11.3.0-11.4.1_HF8;11.0.0-11.2.1_HF14;',
                              'unaffected', '12.0.0;11.6.1;11.6.0_HF5;11.5.4;11.5.3_HF2;11.4.1_HF9;11.2.1_HF15;');

check_f5['APM'] = make_array( 'affected',   '11.6.0-11.6.0_HF4;11.5.0-11.5.3_HF1;11.3.0-11.4.1_HF8;11.0.0-11.2.1_HF14;10.1.0-10.2.4;',
                              'unaffected', '12.0.0;11.6.1;11.6.0_HF5;11.5.4;11.5.3_HF2;11.4.1_HF9;11.2.1_HF15;');

check_f5['ASM'] = make_array( 'affected',   '11.6.0-11.6.0_HF4;11.5.0-11.5.3_HF1;11.3.0-11.4.1_HF8;11.0.0-11.2.1_HF14;10.1.0-10.2.4;',
                              'unaffected', '12.0.0;11.6.1;11.6.0_HF5;11.5.4;11.5.3_HF2;11.4.1_HF9;11.2.1_HF15;');

check_f5['GTM'] = make_array( 'affected',   '11.6.0-11.6.0_HF4;11.5.0-11.5.3_HF1;11.3.0-11.4.1_HF8;11.0.0-11.2.1_HF14;10.1.0-10.2.4;',
                              'unaffected', '11.6.1;11.6.0_HF5;11.5.4;11.5.3_HF2;11.4.1_HF9;11.2.1_HF15;');

check_f5['LC'] = make_array( 'affected',   '11.6.0-11.6.0_HF4;11.5.0-11.5.3_HF1;11.3.0-11.4.1_HF8;11.0.0-11.2.1_HF14;10.1.0-10.2.4;',
                              'unaffected', '12.0.0;11.6.1;11.6.0_HF5;11.5.4;11.5.3_HF2;11.4.1_HF9;11.2.1_HF15;');

check_f5['PEM'] = make_array( 'affected',   '11.6.0-11.6.0_HF4;11.5.0-11.5.3_HF1;11.3.0-11.4.1_HF8;',
                              'unaffected', '12.0.0;11.6.1;11.6.0_HF5;11.5.4;11.5.3_HF2;11.4.1_HF9;');

check_f5['PSM'] = make_array( 'affected',   '11.3.0-11.4.1_HF8;11.0.0-11.2.1_HF14;10.1.0-10.2.4;',
                              'unaffected', '11.4.1_HF9;11.2.1_HF15;');

check_f5['WAM'] = make_array( 'affected',   '11.3.0;11.0.0-11.2.1_HF14;10.1.0-10.2.4;',
                              'unaffected', '11.2.1_HF15;');

check_f5['WOM'] = make_array( 'affected',   '11.3.0;11.0.0-11.2.1_HF14;10.1.0-10.2.4;',
                              'unaffected', '11.2.1_HF15;');

if( report = is_f5_vulnerable( ca:check_f5, version:version ) )
{
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

