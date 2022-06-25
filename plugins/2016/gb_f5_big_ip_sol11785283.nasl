###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_f5_big_ip_sol11785283.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# F5 BIG-IP - SOL11785283 - GnuPG vulnerability CVE-2012-6085
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
  script_oid("1.3.6.1.4.1.25623.1.0.105556");
  script_cve_id("CVE-2012-6085");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_version("$Revision: 12338 $");

  script_name("F5 BIG-IP - SOL11785283 - GnuPG vulnerability CVE-2012-6085");

  script_xref(name:"URL", value:"https://support.f5.com/kb/en-us/solutions/public/k/11/sol11785283.html?sr=51723047");

  script_tag(name:"impact", value:"A remote attacker may exploit this vulnerability by way of a specially crafted OpenPGP packet to cause the keyring to be corrupted.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The read_block function in g10/import.c in GnuPG 1.4.x before 1.4.13 and 2.0.x through 2.0.19, when importing a key, allows remote attackers to corrupt the public keyring database or cause a denial of service (application crash) via a crafted length field of an OpenPGP packet.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"The remote host is missing a security patch.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-02-23 10:37:05 +0100 (Tue, 23 Feb 2016)");
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

check_f5['LTM'] = make_array( 'affected',   '12.0.0-12.1.0;11.0.0-11.4.1;10.1.0-10.2.4;',
                              'unaffected', '11.5.0-11.6.0;');

check_f5['AAM'] = make_array( 'affected',   '12.0.0-12.1.0;11.4.0-11.4.1;',
                              'unaffected', '11.5.0-11.6.0;');

check_f5['AFM'] = make_array( 'affected',   '12.0.0-12.1.0;11.3.0-11.4.1;',
                              'unaffected', '11.5.0-11.6.0;');

check_f5['AVR'] = make_array( 'affected',   '12.0.0-12.1.0;11.0.0-11.4.1;',
                              'unaffected', '11.5.0-11.6.0;');

check_f5['APM'] = make_array( 'affected',   '12.0.0-12.1.0;11.0.0-11.4.1;10.1.0-10.2.4;',
                              'unaffected', '11.5.0-11.6.0;');

check_f5['ASM'] = make_array( 'affected',   '12.0.0-12.1.0;11.0.0-11.4.1;',
                              'unaffected', '11.5.0-11.6.0;');

check_f5['GTM'] = make_array( 'affected',   '11.0.0-11.4.1;10.1.0-10.2.4;',
                              'unaffected', '11.5.0-11.6.0;');

check_f5['LC'] = make_array( 'affected',   '12.0.0-12.1.0;11.0.0-11.4.1;10.1.0-10.2.4;',
                              'unaffected', '11.5.0-11.6.0;');

check_f5['PEM'] = make_array( 'affected',   '12.0.0-12.1.0;11.3.0-11.4.1;',
                              'unaffected', '11.5.0-11.6.0;');

if( report = is_f5_vulnerable( ca:check_f5, version:version ) )
{
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
