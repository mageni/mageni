###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_searchblox_mult_vuln_sept13.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# SearchBlox Multiple Vulnerabilities Sept-13
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802060");
  script_version("$Revision: 11865 $");
  script_bugtraq_id(61973, 61974, 61975);
  script_cve_id("CVE-2013-3598", "CVE-2013-3597", "CVE-2013-3590");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-09-03 10:46:51 +0530 (Tue, 03 Sep 2013)");
  script_name("SearchBlox Multiple Vulnerabilities Sept-13");

  script_tag(name:"summary", value:"This host is running SearchBlox and is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to
  get confidential information.");
  script_tag(name:"solution", value:"Upgrade to SearchBlox version 7.5 build 1 or later.");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Input passed via 'name' parameter to 'servlet/CreateTemplateServlet' not
  properly sanitised before being used to create files.

  - Error when accessing 'servlet/CollectionListServlet' servlet when 'action'
  is set to 'getList' can be exploited to disclose usernames and passwords
  from the database.

  - 'admin/uploadImage.html' script allows to upload an executable file with the
  image/jpeg content type and it can be exploited to execute arbitrary JSP
  code by uploading a malicious JSP script.");
  script_tag(name:"affected", value:"SearchBlox before 7.5 build 1");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary JSP code or
  obtain potentially sensitive information or can overwrite arbitrary files
  via directory traversal sequences.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54629");
  script_xref(name:"URL", value:"http://www.searchblox.com/developers-2/change-log");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

foreach dir (make_list_unique("/", "/search", "/searchblox", cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";

  req = http_get(item:dir + "/searchblox/search.html",  port:http_port);
  res = http_keepalive_send_recv(port:http_port, data:req, bodyonly:TRUE);

  if( 'action="servlet/SearchServlet"' >< res &&
      'id="searchPageCollectionList"' >< res )
  {
    url = dir + '/searchblox/servlet/CollectionListServlet?action=getList' +
                '&orderBy=colName&direction=asc';

    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
                       pattern:"scanner-auth-password",
                       extra_check: make_list("rootURLStr1",
                       'scanner-user-agent":"SearchBlox')))
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);