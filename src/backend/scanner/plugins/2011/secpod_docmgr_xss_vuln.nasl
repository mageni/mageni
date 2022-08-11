##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_docmgr_xss_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# DocMGR Cross Site Scripting Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.902391");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("DocMGR Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44584/");
  script_xref(name:"URL", value:"http://www.naked-security.com/nsa/198631.htm");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101457/docMGR1.1.2-XSS.txt");

  script_tag(name:"insight", value:"The flaw is caused by an input validation error while processing
  the 'f' parameter in 'history.php', allows attackers to send specially crafted
  HTTP request to the vulnerable application.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running DocMGR is prone to cross-site scripting
  vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary html and scripting code in user's browser in context of a vulnerable website.");
  script_tag(name:"affected", value:"DocMGR version 1.1.2 and prior.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/docmgr", "/DocMGR", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item:dir + "/index.php", port:port );

  if( ">Welcome to DocMGR" >< rcvRes ) {

    url = dir + '/history.php?f=0");}alert("xss-test");{//';

    sndReq = http_get( item:url , port:port );
    rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

    if(rcvRes =~ "HTTP/1\.. 200" &&  '}alert("xss-test");' >< rcvRes ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
