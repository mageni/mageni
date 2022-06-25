###############################################################################
# OpenVAS Vulnerability Test
# $Id: interscan_vw_cgi.nasl 12828 2018-12-18 14:49:09Z cfischer $
#
# InterScan VirusWall Remote Configuration Vulnerability
#
# Authors:
# Gregory Duchemin <plugin@intranode.com>
#
# Copyright:
# Copyright (C) 2001 INTRANODE
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.10733");
  script_version("$Revision: 12828 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 15:49:09 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2579);
  script_cve_id("CVE-2001-0432");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("InterScan VirusWall Remote Configuration Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 INTRANODE");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Don't connect the management interface directly to the Internet.");

  script_tag(name:"summary", value:"The management interface used with the Interscan VirusWall
  uses several cgi programs that may allow a malicious user to remotely change the configuration
  of the server without any authorization using maliciously constructed querystrings.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

url = "/interscan/cgi-bin/FtpSave.dll?I'm%20Here";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( "These settings have been saved" >< res ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );