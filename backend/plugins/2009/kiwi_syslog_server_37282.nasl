###############################################################################
# OpenVAS Vulnerability Test
# $Id: kiwi_syslog_server_37282.nasl 14325 2019-03-19 13:35:02Z asteins $
#
# Kiwi Syslog Server Information Disclosure Weakness and Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100391");
  script_version("$Revision: 14325 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:35:02 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-12-11 12:55:06 +0100 (Fri, 11 Dec 2009)");
  script_bugtraq_id(37282);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Kiwi Syslog Server Information Disclosure Weakness and Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8088);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37282");
  script_xref(name:"URL", value:"http://www.kiwisyslog.com/kiwi-syslog-server-overview/");

  script_tag(name:"summary", value:"Kiwi Syslog Server is prone to an information-disclosure weakness and
  vulnerability.

  1) The weakness is due to the Web Access login page displaying
  different messages when invalid usernames or passwords are submitted.
  This can be exploited to enumerate user accounts.

  2) A security issue is due to the Cassini Explorer of the
  embedded UltiDev Cassini Web Server being enabled. This can be
  exploited to access the administrative interface and e.g. disclose the
  content of local files by registering a new application.");
  script_tag(name:"impact", value:"An attacker can exploit these vulnerabilities to obtain information
  that may aid in further attacks.");
  script_tag(name:"affected", value:"Kiwi Syslog Server 9.0.3 is vulnerable, other versions may also
  be affected.");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:8088 );
if( ! can_host_asp( port:port ) ) exit( 0 );

url = string("/gateway.aspx");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if( buf == NULL ) exit( 0 );

if(egrep(pattern: "Kiwi Syslog Web Access", string: buf, icase: TRUE)) {

  url = string("/gateway.aspx?__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwULLTIwNjUwMjM1NjQPZBYCAgMPZBYCAgEPPCsACgEADxYEHgtGYWlsdXJlVGV4dGUeCFVzZXJOYW1lBQ1BZG1pbmlzdHJhdG9yZGQYAQUeX19Db250cm9sc1JlcXVpcmVQb3N0QmFja0tleV9fFgEFGktpd2lMb2dpbiRMb2dpbkltYWdlQnV0dG9uShEYDrwkbsaKaqfUKt%2Bm01b9E0k%3D&KiwiLogin%24UserName=Administrator&KiwiLogin%24Password=BB21158C733229347BD4E681891E213D94C685BE&KiwiLogin%24LoginButton=Log+In&__EVENTVALIDATION=%2FwEWBAL30dbnBgKygMn2DQK9xr32DgK3tbCVAqYdJ5Ze%2Fb7UR1MSh90V%2B%2Fg1SA%2Fb");
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  message = eregmatch(pattern: "showBalloonHelp.*Authentication Failed.  ([^.]+)", string: buf);
  if(isnull(message[1]))exit(0);
  p = message[1];

  url = string("/gateway.aspx?__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwULLTIwNjUwMjM1NjQPZBYCAgMPZBYCAgEPPCsACgEADxYEHgtGYWlsdXJlVGV4dGUeCFVzZXJOYW1lBQ1BZG1pbmlzdHJhdG9yZGQYAQUeX19Db250cm9sc1JlcXVpcmVQb3N0QmFja0tleV9fFgEFGktpd2lMb2dpbiRMb2dpbkltYWdlQnV0dG9uShEYDrwkbsaKaqfUKt%2Bm01b9E0k%3D&KiwiLogin%24UserName=Administrato&KiwiLogin%24Password=BB21158C733229347BD4E681891E213D94C685BE&KiwiLogin%24LoginButton=Log+In&__EVENTVALIDATION=%2FwEWBAL30dbnBgKygMn2DQK9xr32DgK3tbCVAqYdJ5Ze%2Fb7UR1MSh90V%2B%2Fg1SA%2Fb");
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  message = eregmatch(pattern: "showBalloonHelp.*Authentication Failed.  ([^.]+)", string: buf);
  if(isnull(message[1]))exit(0);
  u = message[1];

  if(p != u) {
    security_message(port: port);
    exit(0);
  }
}

exit( 99 );
