###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_f5_big_ip_sol31026324.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# F5 BIG-IP - SOL31026324 - Linux kernel vulnerabilities CVE-2015-2925, CVE-2015-5307, and CVE-2015-8104
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
  script_oid("1.3.6.1.4.1.25623.1.0.105517");
  script_cve_id("CVE-2015-2925", "CVE-2015-5307", "CVE-2015-8104");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12096 $");

  script_name("F5 BIG-IP - SOL31026324 - Linux kernel vulnerabilities CVE-2015-2925, CVE-2015-5307, and CVE-2015-8104");

  script_xref(name:"URL", value:"https://support.f5.com/kb/en-us/solutions/public/k/31/sol31026324.html");

  script_tag(name:"impact", value:"A local user may be able to bypass a container protection mechanism by renaming a directory, or cause a denial-of-service (DoS) to the system by triggering certain exceptions.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2015-2925
The prepend_path function in fs/dcache.c in the Linux kernel before 4.2.4 does not properly handle rename actions inside a bind mount, which allows local users to bypass an intended container protection mechanism by renaming a directory, related to a 'double-chroot attack'.

CVE-2015-5307
The KVM subsystem in the Linux kernel through 4.2.6, and Xen 4.3.x through 4.6.x, allows guest OS users to cause a denial of service (host OS panic or hang) by triggering many #AC (aka Alignment Check) exceptions, related to svm.c and vmx.c.

CVE-2015-8104
The KVM subsystem in the Linux kernel through 4.2.6, and Xen 4.3.x through 4.6.x, allows guest OS users to cause a denial of service (host OS panic or hang) by triggering many #DB (aka Debug) exceptions, related to svm.c.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"The remote host is missing a security patch.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-01-19 12:04:32 +0100 (Tue, 19 Jan 2016)");
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

check_f5['LTM'] = make_array( 'affected',   '12.0.0;11.1.0-11.6.0;',
                              'unaffected', '12.1.0;12.0.0_HF3;11.0.0;10.1.0-10.2.4;');

check_f5['AAM'] = make_array( 'affected',   '12.0.0;11.4.0-11.6.0;',
                              'unaffected', '12.1.0;12.0.0_HF3;');

check_f5['AFM'] = make_array( 'affected',   '12.0.0;11.3.0-11.6.0;',
                              'unaffected', '12.1.0;12.0.0_HF3;');

check_f5['AVR'] = make_array( 'affected',   '12.0.0;11.1.0-11.6.0;',
                              'unaffected', '12.1.0;12.0.0_HF3;11.0.0;');

check_f5['APM'] = make_array( 'affected',   '12.0.0;11.1.0-11.6.0;',
                              'unaffected', '12.1.0;12.0.0_HF3;11.0.0;10.1.0-10.2.4;');

check_f5['ASM'] = make_array( 'affected',   '12.0.0;11.1.0-11.6.0;',
                              'unaffected', '12.1.0;12.0.0_HF3;11.0.0;10.1.0-10.2.4;');

check_f5['GTM'] = make_array( 'affected',   '11.1.0-11.6.0;',
                              'unaffected', '11.0.0;10.1.0-10.2.4;');

check_f5['LC'] = make_array( 'affected',   '12.0.0;11.1.0-11.6.0;',
                              'unaffected', '12.1.0;12.0.0_HF3;11.0.0;10.1.0-10.2.4;');

check_f5['PEM'] = make_array( 'affected',   '12.0.0;11.3.0-11.6.0;',
                              'unaffected', '12.1.0;12.0.0_HF3;');

check_f5['PSM'] = make_array( 'affected',   '11.1.0-11.4.1;',
                              'unaffected', '11.0.0;10.1.0-10.2.4;');

check_f5['WAM'] = make_array( 'affected',   '11.1.0-11.3.0;',
                              'unaffected', '11.0.0;10.1.0-10.2.4;');

check_f5['WOM'] = make_array( 'affected',   '11.1.0-11.3.0;',
                              'unaffected', '11.0.0;10.1.0-10.2.4;');

if( report = is_f5_vulnerable( ca:check_f5, version:version ) )
{
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

