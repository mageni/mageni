###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_f5_big_ip_sol21485342.nasl 11922 2018-10-16 10:24:25Z asteins $
#
# F5 BIG-IP - SOL21485342 - Configuration utility CSRF vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.140053");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11922 $");

  script_name("F5 BIG-IP - SOL21485342 - Configuration utility CSRF vulnerability");

  script_xref(name:"URL", value:"https://support.f5.com/kb/en-us/solutions/public/k/21/sol21485342.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"When an authenticated Configuration utility user visits a specially crafted web page, the user's current session can be logged out and unknowingly logged in to the Configuration utility using a different user account.");
  script_tag(name:"impact", value:"When exploited, the authenticated Configuration utility user's login session is replaced by another user account without the targeted user's knowledge. To exploit this cross-site request forgery (CSRF) vulnerability, an attacker must already know the login credentials of a legitimate Configuration utility user account.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-16 12:24:25 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-11-09 15:02:57 +0100 (Wed, 09 Nov 2016)");
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

check_f5['LTM'] = make_array( 'affected',   '11.6.0-11.6.1;11.5.4-11.5.4_HF1;11.4.0-11.5.3;11.2.1;10.2.1-10.2.4;',
                              'unaffected', '12.0.0-12.1.1;11.6.1_HF1;11.5.4_HF2;');

check_f5['AAM'] = make_array( 'affected',   '11.6.0-11.6.1;11.5.4-11.5.4_HF1;11.4.0-11.5.3;',
                              'unaffected', '12.0.0-12.1.1;11.6.1_HF1;11.5.4_HF2;');

check_f5['AFM'] = make_array( 'affected',   '11.6.0-11.6.1;11.5.4-11.5.4_HF1;11.4.0-11.5.3;',
                              'unaffected', '12.0.0-12.1.1;11.6.1_HF1;11.5.4_HF2;');

check_f5['AVR'] = make_array( 'affected',   '11.6.0-11.6.1;11.5.4-11.5.4_HF1;11.4.0-11.5.3;11.2.1;',
                              'unaffected', '12.0.0-12.1.1;11.6.1_HF1;11.5.4_HF2;');

check_f5['APM'] = make_array( 'affected',   '11.6.0-11.6.1;11.5.4-11.5.4_HF1;11.4.0-11.5.3;11.2.1;10.2.1-10.2.4;',
                              'unaffected', '12.0.0-12.1.1;11.6.1_HF1;11.5.4_HF2;');

check_f5['ASM'] = make_array( 'affected',   '11.6.0-11.6.1;11.5.4-11.5.4_HF1;11.4.0-11.5.3;11.2.1;10.2.1-10.2.4;',
                              'unaffected', '12.0.0-12.1.1;11.6.1_HF1;11.5.4_HF2;');

check_f5['GTM'] = make_array( 'affected',   '11.6.0-11.6.1;11.5.4-11.5.4_HF1;11.4.0-11.5.3;11.2.1;10.2.1-10.2.4;',
                              'unaffected', '11.6.1_HF1;11.5.4_HF2;');

check_f5['LC'] = make_array( 'affected',   '11.6.0-11.6.1;11.5.4-11.5.4_HF1;11.4.0-11.5.3;11.2.1;10.2.1-10.2.4;',
                              'unaffected', '12.0.0-12.1.1;11.6.1_HF1;11.5.4_HF2;');

check_f5['PEM'] = make_array( 'affected',   '11.6.0-11.6.1;11.5.4-11.5.4_HF1;11.4.0-11.5.3;',
                              'unaffected', '12.0.0-12.1.1;11.6.1_HF1;11.5.4_HF2;');

if( report = is_f5_vulnerable( ca:check_f5, version:version ) )
{
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
