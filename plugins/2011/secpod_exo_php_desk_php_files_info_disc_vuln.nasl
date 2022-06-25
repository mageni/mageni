###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_exo_php_desk_php_files_info_disc_vuln.nasl 11987 2018-10-19 11:05:52Z mmartin $
#
# ExoPHPDesk '.php' Files Information Disclosure Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902736");
  script_version("$Revision: 11987 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 13:05:52 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)");
  script_cve_id("CVE-2011-3736");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("ExoPHPDesk '.php' Files Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"https://www.infosecisland.com/alertsview/16767-CVE-2011-3736-exophpdesk.html");
  script_xref(name:"URL", value:"http://code.google.com/p/inspathx/source/browse/trunk/paths_vuln/ExoPHPDesk_1.2.1");
  script_xref(name:"URL", value:"http://securityswebblog.blogspot.com/2011/09/vulnerability-summary-for-cve-2011-3736_26.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to gain sensitive
  information.");
  script_tag(name:"affected", value:"ExoPHPDesk version 1.2.1");
  script_tag(name:"insight", value:"The flaw is due to error in certain '.php' files. A direct request
  to these files reveals the installation path in an error message.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running ExoPHPDesk and is prone to information
  disclosure vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)) {
  exit(0);
}

foreach dir (make_list_unique("/ExoPHPDesk", "/", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"), port:port);

  ## Conform the application
  if("<title>EXO PHPDesk<" >< rcvRes || ">Powered by ExoPHPDesk" >< rcvRes)
  {
    url = dir + "/upgrades/upgrade9.php";

    if(http_vuln_check(port:port, url:url, pattern:"<b>Fatal error</b>:  " +
                 "Call to a member function query().*upgrades/upgrade9.php"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);