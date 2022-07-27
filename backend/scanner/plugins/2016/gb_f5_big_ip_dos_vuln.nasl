###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_f5_big_ip_dos_vuln.nasl 11772 2018-10-08 07:20:02Z asteins $
#
# F5 BIG-IP Denial of Service Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.808180");
  script_version("$Revision: 11772 $");
  script_cve_id("CVE-2016-4545");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-08 09:20:02 +0200 (Mon, 08 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-04 10:59:05 +0530 (Mon, 04 Jul 2016)");
  script_tag(name:"qod_type", value:"package");
  script_name("F5 BIG-IP Denial of Service Vulnerability");

  script_tag(name:"summary", value:"The remote host is running F5 BIG-IP which is
  prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when virtual servers with
  Secure Sockets Layer (SSL) profiles enabled send SSL alert during the
  handshake may produce unnecessary logging and resource consumption.");

  script_tag(name:"impact", value:"Successful exploitation of this flaw will allow
  remote attackers to cause a denial of service (resource consumption and Traffic
  Management Microkernel restart).");

  script_tag(name:"affected", value:"F5 BIG-IP 11.5.4");

  script_tag(name:"solution", value:"Refer the link mentioned in reference for solution
  information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.f5.com/kb/en-us/solutions/public/k/48/sol48042976.html");
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

check_f5['LTM'] = make_array( 'affected',   '11.5.4;',
                              'unaffected', '12.0.0-12.1.0;11.6.0-11.6.1;11.5.4_HF1;11.0.0-11.5.3;10.2.1-10.2.4;');

check_f5['AAM'] = make_array( 'affected',   '11.5.4;',
                              'unaffected', '12.0.0-12.1.0;11.6.0-11.6.1;11.5.4_HF1;11.4.0-11.5.3;');

check_f5['AFM'] = make_array( 'affected',   '11.5.4;',
                              'unaffected', '12.0.0-12.1.0;11.6.0-11.6.1;11.5.4_HF1;11.3.0-11.5.3;');

check_f5['AVR'] = make_array( 'affected',   '11.5.4;',
                              'unaffected', '12.0.0-12.1.0;11.6.0-11.6.1;11.5.4_HF1;11.0.0-11.5.3;');

check_f5['APM'] = make_array( 'affected',   '11.5.4;',
                              'unaffected', '12.0.0-12.1.0;11.6.0-11.6.1;11.5.4_HF1;11.0.0-11.5.3;10.2.1-10.2.4;');

check_f5['ASM'] = make_array( 'affected',   '11.5.4;',
                              'unaffected', '12.0.0-12.1.0;11.6.0-11.6.1;11.5.4_HF1;11.0.0-11.5.3;10.2.1-10.2.4;');

check_f5['GTM'] = make_array( 'affected',   '11.5.4;',
                              'unaffected', '11.6.0-11.6.1;11.5.4_HF1;11.0.0-11.5.3;10.2.1-10.2.4;');

check_f5['LC'] = make_array( 'affected',   '11.5.4;',
                              'unaffected', '12.0.0-12.1.0;11.6.0-11.6.1;11.5.4_HF1;11.0.0-11.5.3;10.2.1-10.2.4;');

check_f5['PEM'] = make_array( 'affected',   '11.5.4;',
                              'unaffected', '12.0.0-12.1.0;11.6.0-11.6.1;11.5.4_HF1;11.3.0-11.5.3;');

if( report = is_f5_vulnerable( ca:check_f5, version:version ) )
{
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
