###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cm3_acoracms_mult_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# CM3 AcoraCMS Multiple XSS, CSRF and Open Redirect Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804268");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2013-4722", "CVE-2013-4723", "CVE-2013-4724", "CVE-2013-4725",
                "CVE-2013-4726", "CVE-2013-4727", "CVE-2013-4728");
  script_bugtraq_id(62008, 62007, 62009, 62011, 62010, 62012, 67701);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-04-29 11:10:25 +0530 (Tue, 29 Apr 2014)");
  script_name("CM3 AcoraCMS Multiple XSS, CSRF and Open Redirect Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122954");
  script_xref(name:"URL", value:"http://www.digitalsec.net/stuff/explt+advs/CM3.AcoraCMS.v6.txt");

  script_tag(name:"summary", value:"This host is installed with CM3 AcoraCMS and is prone to multiple XSS, CSRF
  and url redirection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able
  read the cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Insufficient validation of user-supplied input via 'username', 'url', 'qstr'
  passed to login/default.asp

  - Insufficient validation of the 'l' parameter upon submission to track.aspx
  script.

  - insufficient measures for confirmation of sensitive transactions.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to redirect victim from the
  intended legitimate web site to an arbitrary web site, trick the users into
  performing an unspecified action in the context of their session with the
  application and execute arbitrary script code in a user's browser session
  in context of an affected site.");

  script_tag(name:"affected", value:"CM3 Acora CMS 6.0.6/1a, 6.0.2/1a, 5.5.7/12b, 5.5.0/1b-p1, and possibly other
  versions");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

cmsPort = get_http_port( default:80 );
if( ! can_host_asp( port:cmsPort ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/AcoraCMS", "/cms", cgi_dirs( port:cmsPort ) ) ) {

  if( dir == "/" ) dir = "";

  sndReq = http_get( item:dir + "/Admin/login/default.asp", port:cmsPort );
  rcvRes = http_keepalive_send_recv( port:cmsPort, data:sndReq );

  if( "Welcome to the Acora CMS web-based administration" >< rcvRes ) {

    url = dir + '/Admin/login/default.asp?username="</div><script>alert(document.cookie)</script>';

    if( http_vuln_check( port:cmsPort, url:url, check_header:TRUE, pattern:"<script>alert\(document\.cookie\)</script>",
                         extra_check:">Acora CMS" ) ) {
      report = report_vuln_url( port:cmsPort, url:url );
      security_message( port:cmsPort, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
