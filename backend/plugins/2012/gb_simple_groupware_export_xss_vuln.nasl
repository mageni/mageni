###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simple_groupware_export_xss_vuln.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# SimpleGroupware 'export' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802589");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-1028");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-02-09 17:20:45 +0530 (Thu, 09 Feb 2012)");
  script_name("SimpleGroupware 'export' Parameter Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2012-02/0028.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.");
  script_tag(name:"affected", value:"SimpleGroupware 0.742 and prior.");
  script_tag(name:"insight", value:"The flaw is due to an input passed via 'export' parameter to 'bin/index.php'
  is not properly sanitised before being returned to the user.");
  script_tag(name:"solution", value:"Upgrade to SimpleGroupware version 0.743 or later.");
  script_tag(name:"summary", value:"This host is running SimpleGroupware and is prone to cross site
  scripting vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.simple-groupware.de/cms/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/sgs/sgs_installer.php", "/sgs", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/bin/index.php"), port:port);

  if(rcvRes && ">Powered by Simple Groupware" >< rcvRes)
  {
    url = dir + '/bin/index.php?export=<script>alert(document.cookie)' +
                                                   '</script>';

    if(http_vuln_check(port:port, url:url, pattern:"<script>alert\(" +
                                    "document.cookie\)</script>", check_header:TRUE))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
