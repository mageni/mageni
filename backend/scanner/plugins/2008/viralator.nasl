# OpenVAS Vulnerability Test
# $Id: viralator.nasl 14240 2019-03-17 15:50:45Z cfischer $
# Description: viralator
#
# Authors:
# Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2002 Renaud Deraison
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
#

# References:
# http://marc.info/?l=bugtraq&m=100463639800515&w=2

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80093");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_bugtraq_id(3495);
  script_cve_id("CVE-2001-0849");
  script_name("viralator");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Renaud Deraison");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The CGI 'viralator.cgi' is installed.

  Some versions of this CGI are don't check properly the user input and allow anyone to execute arbitrary commands
  with the privileges of the web server");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade this script to version 0.9pre2 or newer.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
res = is_cgi_installed_ka(item:"viralator.cgi", port:port);
if( res )security_message(port);
