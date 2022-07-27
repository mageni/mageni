##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_labwiki_mult_xss_n_shell_upload_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# LabWiki Multiple Cross-site Scripting (XSS) and Shell Upload Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802402");
  script_version("$Revision: 11997 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-10 12:48:30 +0530 (Thu, 10 Nov 2011)");
  script_name("LabWiki Multiple Cross-site Scripting (XSS) and Shell Upload Vulnerabilities");
  script_xref(name:"URL", value:"https://secunia.com/advisories/46762");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18100/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/520441");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/current/0112.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"The flaws are due to an,

  - Input passed to the 'from' parameter in index.php is not properly sanitised
  before being returned to the user.

  - Input passed to the 'page_no' parameter in recentchanges.php is noti
  properly sanitised before being returned to the user.

  - Input passed to the 'userfile' POST parameter in edit.php is not properly
  verified before being used to upload files.");
  script_tag(name:"solution", value:"Update to version 1.2 or later.");
  script_tag(name:"summary", value:"This host is running LabWiki and is prone to multiple cross-site
  scripting and shell upload vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code in a user's browser session in context of
  affected website and to upload arbitrary PHP files with '.gif' extension.");
  script_tag(name:"affected", value:"LabWiki version 1.1 and prior.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.bioinformatics.org/phplabware/labwiki/index.php");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

labPort = get_http_port(default:80);

if(!can_host_php(port:labPort)){
  exit(0);
}

foreach dir (make_list_unique("/LabWiki", "/labwiki/LabWiki", "/", cgi_dirs(port:labPort)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:labPort);

  if('>My Lab</a' >< rcvRes && '>What is Wiki</' >< rcvRes)
  {
    url = string(dir, '/index.php?from="></><script>alert(document.cookie)' +
                      '</script>&help=true&page=What_is_wiki');

    if(http_vuln_check(port:labPort, url:url, pattern:"><script>alert" +
                       "\(document.cookie\)</script>", check_header:TRUE))
    {
      security_message(port:labPort);
      exit(0);
    }
  }
}

exit(99);
