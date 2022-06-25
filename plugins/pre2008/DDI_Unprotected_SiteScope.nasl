###############################################################################
# OpenVAS Vulnerability Test
# $Id: DDI_Unprotected_SiteScope.nasl 11998 2018-10-20 18:17:12Z cfischer $
#
# Unprotected SiteScope Service
#
# Authors:
# H D Moore
#
# Copyright:
# Copyright (C) 2001 Digital Defense Inc.
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10778");
  script_version("$Revision: 11998 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 20:17:12 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0508");
  script_name("Unprotected SiteScope Service");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2001 Digital Defense Inc.");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8888);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Make sure that a password is set in the configuration
  for this service. Depending on where this server is located,
  you may want to restrict access by IP address in addition to
  username.");

  script_tag(name:"summary", value:"The SiteScope web service has no password set. An attacker
  who can connect to this server could view usernames and
  passwords stored in the preferences section or reconfigure
  the service.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:8888 );

url = "/SiteScope/cgi/go.exe/SiteScope?page=eventLog&machine=&logName=System&account=administrator";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( "Event Log" >< res ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report);
  exit( 0 );
}

exit( 0 );