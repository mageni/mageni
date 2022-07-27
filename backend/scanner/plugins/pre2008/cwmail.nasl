###################################################################
# OpenVAS Vulnerability Test
# $Id: cwmail.nasl 12002 2018-10-21 11:19:34Z cfischer $
#
# CWmail.exe vulnerability
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
#
# Copyright:
# Copyright (C) 2003 John Lampe
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11727");
  script_version("$Revision: 12002 $");
  script_cve_id("CVE-2002-0273");
  script_bugtraq_id(4093);
  script_tag(name:"last_modification", value:"$Date: 2018-10-21 13:19:34 +0200 (Sun, 21 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CWmail.exe vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 John Lampe");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=101362100602008&w=2");

  script_tag(name:"impact", value:"An attacker may make use of this file to gain access to
  confidential data or escalate their privileges on the Web server.");

  script_tag(name:"solution", value:"The vendor has provided a patch to fix this issue.
  Please see the references for more info.");

  script_tag(name:"summary", value:"The CWMail.exe exists on this webserver.
  Some versions of this file are vulnerable to remote exploit.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  url = dir + "/cwmail.exe";

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  if( egrep( pattern:".*CWMail 2\.[0-7]\..*", string:res ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );