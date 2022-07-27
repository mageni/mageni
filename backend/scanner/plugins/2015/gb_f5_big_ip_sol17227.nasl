###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_f5_big_ip_sol17227.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# F5 BIG-IP - SOL17227 - BIND vulnerability CVE-2015-5986
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105359");
  script_cve_id("CVE-2015-5986");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12106 $");

  script_name("F5 BIG-IP - SOL17227 - BIND vulnerability CVE-2015-5986");

  script_xref(name:"URL", value:"https://support.f5.com/kb/en-us/solutions/public/17000/200/sol17227.html?sr=48315203");

  script_tag(name:"impact", value:"A remote attacker may be able to cause a denial-of-service (DoS) attack on the BIG-IP system's local instance of BIND by using a specially crafted DNS request in configurations that expose BIND to requests from untrusted users. If the BIND process (named) terminates or stops responding, the bigstart process will automatically restart the impacted daemon.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An incorrect boundary check in openpgpkey_61.c can cause named to terminate due to a REQUIRE assertion failure.  This defect can be deliberately exploited by an attacker who can provide a maliciously constructed response in answer to a query. (CVE-2015-5986)");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"The remote host is missing a security patch.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-09-18 14:34:25 +0200 (Fri, 18 Sep 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("F5 Local Security Checks");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
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

check_f5['LTM'] = make_array( 'affected',   '12.0.0;11.4.1_HF9;11.2.1_HF15;2;',
                              'unaffected', '12.1.0;12.0.0_HF1;11.5.0-11.6.1;11.4.1_HF10;11.3.0-11.4.1_HF8;11.0.0-11.2.1_HF14,;11.2.1_HF16;10.1.0-10.2.4;');

check_f5['AAM'] = make_array( 'affected',   '12.0.01;11.4.1_HF91;',
                              'unaffected', '12.1.0;12.0.0_HF1;11.5.0-11.6.1;11.4.1_HF10;11.4.0-11.4.1_HF8;');

check_f5['AFM'] = make_array( 'affected',   '12.0.01;11.4.1_HF91;',
                              'unaffected', '12.1.0;12.0.0_HF1;11.5.0-11.6.1;11.4.1_HF10;11.3.0-11.4.1_HF8;');

check_f5['AVR'] = make_array( 'affected',   '12.0.01;11.4.1_HF91;11.2.1_HF151;',
                              'unaffected', '12.1.0;12.0.0_HF1;11.5.0-11.6.1;11.4.1_HF10;11.3.0-11.4.1_HF8;11.0.0-11.2.1_HF14,;11.2.1_HF16;');

check_f5['APM'] = make_array( 'affected',   '12.0.01;11.4.1_HF91;11.2.1_HF151;',
                              'unaffected', '12.1.0;12.0.0_HF1;11.5.0-11.6.1;11.4.1_HF10;11.3.0-11.4.1_HF8;11.0.0-11.2.1_HF14,;11.2.1_HF16;10.1.0-10.2.4;');

check_f5['ASM'] = make_array( 'affected',   '12.0.01;11.4.1_HF91;11.2.1_HF151;',
                              'unaffected', '12.1.0;12.0.0_HF1;11.5.0-11.6.1;11.4.1_HF10;11.3.0-11.4.1_HF8;11.0.0-11.2.1_HF14,;11.2.1_HF16;10.1.0-10.2.4;');

check_f5['GTM'] = make_array( 'affected',   '11.4.1_HF9;11.2.1_HF15;3;',
                              'unaffected', '11.5.0-11.6.1;11.4.1_HF10;11.3.0-11.4.1_HF8;11.0.0-11.2.1_HF14,;11.2.1_HF16;10.1.0-10.2.4;');

check_f5['LC'] = make_array( 'affected',   '12.0.0;11.4.1_HF9;11.2.1_HF15;3;',
                              'unaffected', '12.1.0;12.0.0_HF1;11.5.0-11.6.1;11.4.1_HF10;11.3.0-11.4.1_HF8;11.0.0-11.2.1_HF14,;11.2.1_HF16;10.1.0-10.2.4;');

check_f5['PEM'] = make_array( 'affected',   '12.0.01;11.4.1_HF91;',
                              'unaffected', '12.1.0;12.0.0_HF1;11.5.0-11.6.1;11.4.1_HF10;11.3.0-11.4.1_HF8;');

check_f5['PSM'] = make_array( 'affected',   '11.4.1_HF91;11.2.1_HF151;',
                              'unaffected', '11.4.1_HF10;11.3.0-11.4.1_HF8;11.0.0-11.2.1_HF14,;11.2.1_HF16;10.1.0-10.2.4;');

check_f5['WAM'] = make_array( 'affected',   '11.2.1_HF151;',
                              'unaffected', '11.3.0;11.0.0-11.2.1_HF14,;11.2.1_HF16;10.1.0-10.2.4;');

check_f5['WOM'] = make_array( 'affected',   '11.2.1_HF151;',
                              'unaffected', '11.3.0;11.0.0-11.2.1_HF14,;11.2.1_HF16;10.1.0-10.2.4;');

if( report = is_f5_vulnerable( ca:check_f5, version:version ) )
{
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

