###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webcollab_http_resp_splitting_vuln.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# WebCollab 'item' Parameter HTTP Response Splitting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803773");
  script_version("$Revision: 11888 $");
  script_bugtraq_id(63247);
  script_cve_id("CVE-2013-2652");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-10-28 15:46:55 +0530 (Mon, 28 Oct 2013)");
  script_name("WebCollab 'item' Parameter HTTP Response Splitting Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTTP
  headers, which will be included in a response sent to the user.");
  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it
  is able to inject malicious data in header or not.");
  script_tag(name:"insight", value:"Input passed via the 'item' GET parameter to help/help_language.php is not
  properly sanitised before being returned to the user.");
  script_tag(name:"solution", value:"Upgrade to WebCollab 3.31 or later.");
  script_tag(name:"summary", value:"This host is installed with WebCollab and is prone to HTTP response splitting
  vulnerability.");
  script_tag(name:"affected", value:"WebCollab versions 3.30 and prior.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55235");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Oct/119");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/123771");
  script_xref(name:"URL", value:"http://freecode.com/projects/webcollab/releases/358621");
  script_xref(name:"URL", value:"http://sourceforge.net/p/webcollab/mailman/message/31536457");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/webcollab-330-http-response-splitting");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://webcollab.sourceforge.net");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

if(!can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/webcollab", "/WebCollab", cgi_dirs(port:http_port)))
{
  if(dir == "/") dir = "";

   res = http_get_cache(item:string(dir, "/index.php"),  port: http_port);

   if(res && egrep(pattern:">WebCollab<", string:res))
   {
     url = dir + '/help/help_language.php?item=%0d%0a%20FakeHeader%3a%20' +
           'Fakeheaderis%20injected&amp;lang=en&amp;type=help';

     if(http_vuln_check(port:http_port, url:url, pattern:"FakeHeader: Fakeheaderis injected",
       extra_check:">WebCollab<"))
     {
       security_message(port:http_port);
       exit(0);
     }
  }
}

exit(99);