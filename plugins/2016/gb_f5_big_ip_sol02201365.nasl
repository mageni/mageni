###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_f5_big_ip_sol02201365.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# F5 BIG-IP - SOL02201365 - SLOTH: TLS 1.2 handshake vulnerability CVE-2015-7575
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
  script_oid("1.3.6.1.4.1.25623.1.0.105549");
  script_cve_id("CVE-2015-7575");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 12096 $");

  script_name("F5 BIG-IP - SOL02201365 - SLOTH: TLS 1.2 handshake vulnerability CVE-2015-7575");

  script_xref(name:"URL", value:"https://support.f5.com/kb/en-us/solutions/public/k/02/sol02201365.html?sr=51595235");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the way TLS 1.2 uses RSA+MD5 signatures with Client Authentication and ServerKeyExchange messages during a TLS 1.2 handshakes. An attacker with a Man-in-the-Middle network position and the ability to force / observe the use of RSA+MD5 during a TLS Handshake, may be able to successfully generate a hash collision and impersonate a TLS client or server. The vulnerability of CVE-2015-7575 is relevant to cryptography software which supports TLS 1.2 only as earlier versions of TLS used different hash functionality in those protocols.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"The remote host is missing a security patch.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-02-16 16:20:45 +0100 (Tue, 16 Feb 2016)");
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

check_f5['LTM'] = make_array( 'affected',   '11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;',
                              'unaffected', '12.0.0-12.1.0;11.5.1_HF3-11.6.0;11.5.0_HF4-11.5.0_HF7;11.0.0-11.4.1;10.1.0-10.2.4;');

check_f5['AAM'] = make_array( 'affected',   '11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;',
                              'unaffected', '12.0.0-12.1.0;11.5.1_HF3-11.6.0;11.5.0_HF4-11.5.0_HF7;11.4.0-11.4.1;');

check_f5['AFM'] = make_array( 'affected',   '11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;',
                              'unaffected', '12.0.0-12.1.0;11.5.1_HF3-11.6.0;11.5.0_HF4-11.5.0_HF7;11.3.0-11.4.1;');

check_f5['AVR'] = make_array( 'affected',   '11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;',
                              'unaffected', '12.0.0-12.1.0;11.5.1_HF3-11.6.0;11.5.0_HF4-11.5.0_HF7;11.0.0-11.4.1;');

check_f5['APM'] = make_array( 'affected',   '11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;',
                              'unaffected', '12.0.0-12.1.0;11.5.1_HF3-11.6.0;11.5.0_HF4-11.5.0_HF7;11.0.0-11.4.1;10.1.0-10.2.4;');

check_f5['ASM'] = make_array( 'affected',   '11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;',
                              'unaffected', '12.0.0-12.1.0;11.5.1_HF3-11.6.0;11.5.0_HF4-11.5.0_HF7;11.0.0-11.4.1;10.1.0-10.2.4;');

check_f5['GTM'] = make_array( 'affected',   '11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;',
                              'unaffected', '11.5.1_HF3-11.6.0;11.5.0_HF4-11.5.0_HF7;11.0.0-11.4.1;10.1.0-10.2.4;');

check_f5['LC'] = make_array( 'affected',   '11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;',
                              'unaffected', '12.0.0-12.1.0;11.5.1_HF3-11.6.0;11.5.0_HF4-11.5.0_HF7;11.0.0-11.4.1;10.1.0-10.2.4;');

check_f5['PEM'] = make_array( 'affected',   '11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;',
                              'unaffected', '12.0.0-12.1.0;11.5.1_HF3-11.6.0;11.5.0_HF4-11.5.0_HF7;11.3.0-11.4.1;');

if( report = is_f5_vulnerable( ca:check_f5, version:version ) )
{
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
