###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_f5_big_ip_K82851041.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# F5 BIG-IP - TMM vulnerability CVE-2017-6137
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107207");
  script_cve_id("CVE-2017-6137");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 12106 $");

  script_name("F5 BIG-IP - TMM vulnerability CVE-2017-6137");

  script_xref(name:"URL", value:"https://support.f5.com/csp/article/K82851041");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"Undisclosed traffic patterns received while software SYN cookie protection is
engaged may cause a disruption of service to the Traffic Management Microkernel (TMM) on specific platforms and
configurations. (CVE-2017-6137)");

  script_tag(name:"impact", value:"When software syncookie protection is activated for a virtual server (the
connection.syncookies.threshold database value has been exceeded), and the unit also has the Traffic Management
Microkernel (TMM) fast forward enabled (the tmm.ffwd.enable database value is true, the default), and TCP
Segmentation Offload (TSO) is enabled (the tm.tcpsegmentationoffload database value is true, the default) a
specific sequence of packets causes TMM to generate an egress packet with an invalid MSS. As a result, packets
egressing the BIG-IP system with an invalid MSS may be dropped by a neighboring device. Additionally, on the 3900,
6900, 8900, 8950, 11000, and 11050 platforms this may cause the high-speed bridge (HSB) to lock up.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-29 14:28:20 +0200 (Mon, 29 May 2017)");

  script_category(ACT_GATHER_INFO);
  script_family("F5 Local Security Checks");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
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

check_f5['LTM'] = make_array( 'affected',   '12.1.0-12.1.2;12.0.0_HF3;12.0.0_HF4;11.6.1_HF1;',
                              'unaffected', '13.0.0;12.1.2_HF1;11.6.1_HF2;11.4.0-11.6.1;11.2.1;');

check_f5['AAM'] = make_array( 'affected',   '12.1.0-12.1.2;12.0.0_HF3;12.0.0_HF4;11.6.1_HF1;',
                              'unaffected', '13.0.0;12.1.2_HF1;11.6.1_HF2;11.4.0-11.6.1;');


check_f5['AFM'] = make_array( 'affected',   '12.1.0-12.1.2;12.0.0_HF3;12.0.0_HF4;11.6.1_HF1;',
                              'unaffected', '13.0.0;12.1.2_HF1;11.6.1_HF2;11.4.0-11.6.1;');


check_f5['AVR'] = make_array( 'affected',   '12.1.0-12.1.2;12.0.0_HF3;12.0.0_HF4;11.6.1_HF1;',
                              'unaffected', '13.0.0;12.1.2_HF1;11.6.1_HF2;11.4.0-11.6.1;11.2.1;');


check_f5['APM'] = make_array( 'affected',   '12.1.0-12.1.2;12.0.0_HF3;12.0.0_HF4;11.6.1_HF1;',
                              'unaffected', '13.0.0;12.1.2_HF1;11.6.1_HF2;11.4.0-11.6.1;11.2.1;');


check_f5['ASM'] = make_array( 'affected',   '12.1.0-12.1.2;12.0.0_HF3;12.0.0_HF4;11.6.1_HF1;',
                              'unaffected', '13.0.0;12.1.2_HF1;11.6.1_HF2;11.4.0-11.6.1;11.2.1;');


check_f5['LC'] = make_array( 'affected',   '12.1.0-12.1.2;12.0.0_HF3;12.0.0_HF4;11.6.1_HF1;',
                              'unaffected', '13.0.0;12.1.2_HF1;11.6.1_HF2;11.4.0-11.6.1;11.2.1;');


check_f5['PEM'] = make_array( 'affected',   '12.1.0-12.1.2;12.0.0_HF3;12.0.0_HF4;11.6.1_HF1;',
                              'unaffected', '13.0.0;12.1.2_HF1;11.6.1_HF2;11.4.0-11.6.1;');


if( report = is_f5_vulnerable( ca:check_f5, version:version ) ) {
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

