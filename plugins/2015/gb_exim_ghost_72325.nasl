###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_exim_ghost_72325.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# GNU glibc Remote Heap Buffer Overflow Vulnerability (Exim)
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

CPE = 'cpe:/a:exim:exim';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105188");
  script_bugtraq_id(72325);
  script_cve_id("CVE-2015-0235");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11872 $");

  script_name("GNU glibc Remote Heap Buffer Overflow Vulnerability (Exim)");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72325");
  script_xref(name:"URL", value:"http://www.gnu.org/software/libc/");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code in the
context of the affected application. Failed exploit attempts may crash the application, denying service
 to legitimate users.");

  script_tag(name:"vuldetect", value:"Send a special crafted HELO request and check the response");
  script_tag(name:"solution", value:"Update you glibc and reboot.");
  script_tag(name:"summary", value:"The remote exim is using a version of glibc which is prone to a heap-based buffer-overflow
vulnerability.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-01-29 15:17:02 +0100 (Thu, 29 Jan 2015)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("SMTP problems");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_exim_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_mandatory_keys("exim/installed");

  exit(0);
}

include("smtp_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

recv( socket:soc, length:512 );

send( socket:soc, data:'HELO FOOBAR\r\n' );
recv = recv( socket:soc, length:512 );
close( soc );

if( "550 HELO argument does not match calling host" >!< recv ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

recv = recv( socket:soc, length:512 );

req = 'HELO ' + crap( data:"0", length:1235 ) + '\r\n';

for( i = 1; i < 5; i++ )
{
  send( socket:soc, data:req );
  recv = recv( socket:soc, length:512 );

  if( ! recv )
  {
    if( ( i == 2 || i == 4 ) && socket_get_error( soc ) == ECONNRESET ) # 2 times for 32bit, 4 times for 64bit
    {
      close( soc );
      security_message( port:port );
      exit( 0 );
    }
  }
}

if( soc ) close( soc );

exit( 99 );
