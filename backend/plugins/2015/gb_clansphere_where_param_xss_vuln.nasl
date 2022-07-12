###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clansphere_where_param_xss_vuln.nasl 11423 2018-09-17 07:35:16Z cfischer $
#
# ClanSphere 'where' Parameter Cross-Site Scripting Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805130");
  script_version("$Revision: 11423 $");
  script_cve_id("CVE-2014-100010");
  script_bugtraq_id(66058);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 09:35:16 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-01-23 17:16:23 +0530 (Fri, 23 Jan 2015)");
  script_name("ClanSphere 'where' Parameter Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"The host is installed with ClanSphere
  and is prone to xss vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Input passed via the 'where' parameter to
  '/index.php' is not properly sanitised before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a users browser session
  in the context of an affected site.");

  script_tag(name:"affected", value:"ClanSphere version 2011.4, Prior versions
  may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57306");
  script_xref(name:"URL", value:"https://www.httpcs.com/advisory/httpcs127");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Mar/73");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/531373/100/0/threaded");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

if(!can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/clansphere", "/cms", cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"),  port:http_port);

  if(">csphere" >< rcvRes && "Seitentitel. All rights reserved" >< rcvRes)
  {
    url = dir + '/index.php?sort=6&action=list&where="><script>'
              + 'alert(document.cookie)</script>&mod=users';

    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
      pattern:"<script>alert\(document\.cookie\)</script>",
      extra_check:">csphere"))
    {
      report = report_vuln_url( port:http_port, url:url );
      security_message(port:http_port, data:report);
      exit(0);
    }
  }
}

exit(99);
