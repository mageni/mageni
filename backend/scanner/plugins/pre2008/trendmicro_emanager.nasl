###############################################################################
# OpenVAS Vulnerability Test
# $Id: trendmicro_emanager.nasl 11999 2018-10-21 09:01:06Z cfischer $
#
# Trend Micro Emanager software check
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11747");
  script_version("$Revision: 11999 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-21 11:01:06 +0200 (Sun, 21 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3327);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0958");
  script_name("Trend Micro Emanager software check");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 John Lampe");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3327");

  script_tag(name:"solution", value:"Remove this CGI or upgrade to the latest version of this software");

  script_tag(name:"summary", value:"The Trend Micro Emanager software resides on this server.
  Some versions of this software have vulnerable dlls.");

  script_tag(name:"impact", value:"If vulnerable, remote exploit is possible. Please see the references
  for more info.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

# Old files which were never checked:
#file[1] = "ContentFilter.dll";
#file[2] = "SFNofitication.dll";
#file[3] = "TOP10.dll";
#file[4] = "SpamExcp.dll";
#file[5] = "spamrule.dll";

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", "/eManager/Email%20Management", "/eManager/Content%20Management", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/register.dll";

  if( is_cgi_installed_ka( item:url, port:port ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );