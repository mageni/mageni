###############################################################################
# OpenVAS Vulnerability Test
# $Id: foxweb_dll.nasl 11998 2018-10-20 18:17:12Z cfischer $
#
# foxweb CGI
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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

# References:
# Date:	 Fri, 05 Sep 2003 09:41:37 +0800
# From:	"pokleyzz" <pokleyzz@scan-associates.net>
# To:	bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: [SCAN Associates Sdn Bhd Security Advisory] Foxweb 2.5 bufferoverflow in CGI and ISAPI extension

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11939");
  script_version("$Revision: 11998 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 20:17:12 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(8547);
  script_cve_id("CVE-2010-1898");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("foxweb CGI");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Remove it from /cgi-bin or upgrade it.");

  script_tag(name:"summary", value:"The foxweb.dll or foxweb.exe CGI is installed.

  Versions 2.5 and below of this CGI program have a security flaw
  that lets an attacker execute arbitrary code on the remote server.

  ** Since the scanner just verified the presence of the CGI but could

  ** not check the version number, this might be a false alarm.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach cgi( make_list( "foxweb.dll", "foxweb.exe") ) {

  res = is_cgi_installed_ka( item:cgi, port:port );
  if( res ) {
    report = report_vuln_url( port:port, url:"/" + cgi );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );