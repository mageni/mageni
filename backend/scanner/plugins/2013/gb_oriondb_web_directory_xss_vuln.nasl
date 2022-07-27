###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oriondb_web_directory_xss_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# OrionDB Web Directory Cross Site Scripting Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803458");
  script_version("$Revision: 11401 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-04-01 10:55:57 +0530 (Mon, 01 Apr 2013)");
  script_name("OrionDB Web Directory Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120962");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/oriondb-business-directory-script-cross-site-scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected
  site.");
  script_tag(name:"affected", value:"OrionDB Web Directory");
  script_tag(name:"insight", value:"Input passed via 'c' and 'searchtext' parameters to index.php
  is not properly sanitized before being returned to the user.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with oriondb web directory and is prone
  to cross site scripting vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/oriondb", "/mwd", "/db", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item:string(dir,"/index.php"), port:port);

  if("OrionDB Web Directory<" >< res)
  {
    url = dir + "/index.php?c=<script>alert(document.cookie)</script>";

    if(http_vuln_check(port:port, url:url, check_header:TRUE,
           pattern:"<script>alert\(document\.cookie\)</script>"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
