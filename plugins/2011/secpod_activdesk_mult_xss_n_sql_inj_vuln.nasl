###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_activdesk_mult_xss_n_sql_inj_vuln.nasl 11987 2018-10-19 11:05:52Z mmartin $
#
# ActivDesk Multiple Cross Site Scripting and SQL Injection Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.902530");
  script_version("$Revision: 11987 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 13:05:52 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_cve_id("CVE-2011-1563", "CVE-2011-1564");
  script_bugtraq_id(46937);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("ActivDesk Multiple Cross Site Scripting and SQL Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45057/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17443/");
  script_xref(name:"URL", value:"http://itsecuritysolutions.org/2011-06-24-ActivDesk-3.0-multiple-security-vulnerabilities/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation allow an attacker to steal cookie-based authentication
  credentials, compromise the application, access or modify data, or exploit
  latent vulnerabilities in the underlying database.");
  script_tag(name:"affected", value:"ActivDesk version 3.0 and prior.");
  script_tag(name:"insight", value:"Multiple flaws are due to

  - Improper validation of user-supplied input passed to the 'keywords0',
    'keywords1', 'keywords2' and 'keywords3' parameters in search.cgi,
    which allows attackers to execute arbitrary HTML and script code on
    the web server.

  - Improper validation of user-supplied input passed to the 'cid' parameter
    in kbcat.cgi and the 'kid' parameter in kb.cgi, which allows attacker to
    manipulate SQL queries by injecting arbitrary SQL code.");
  script_tag(name:"solution", value:"Upgrade to ActivDesk version 3.0.1 or later.");
  script_tag(name:"summary", value:"This host is running ActivDesk and is prone to multiple cross site
  scripting and SQL injection vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.webhelpdesk-software.com/download.html");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach dir (make_list_unique("/adesk", "/support", "/hdesk", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  req = http_get(item: dir + "/login.cgi",  port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  if("<title>Support</title>" >< res)
  {
    url = dir + "/search.cgi?keywords0=<script>alert(document.cookie)</script>";

    if(http_vuln_check(port: port, url: url, check_header: TRUE,
       pattern: "<script>alert\(document.cookie\)</script>"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);