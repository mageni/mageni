# OpenVAS Vulnerability Test
# $Id: cobalt_cube_webmail_dir_trav.nasl 11751 2018-10-04 12:03:41Z jschulte $
# Description: readmsg.php detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added link to the Bugtraq message archive
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
# Date:  Thu, 05 Jul 2001 03:41:50 -0400
# From: "KF" <dotslash@snosoft.com>
# To: bugtraq@securityfocus.com, recon@snosoft.com
# Subject: Cobalt Cube Webmail directory traversal

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11073");
  script_version("$Revision: 11751 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-04 14:03:41 +0200 (Thu, 04 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2001-1408");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("readmsg.php detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 444);

  script_tag(name:"solution", value:"get a newer software from Cobalt");
  script_tag(name:"summary", value:"/base/webmail/readmsg.php was detected.
  Some versions of this CGI allow remote users to read local
  files with the permission of the web server.
  Note that if the user has a shell access, this kind of attack is
  not interesting.

  *** Just checked the presence of this file
  *** but did not try to exploit the flaw.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://online.securityfocus.com/archive/1/195165");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:444);

if ( ! can_host_php(port:port) ) exit(0);

url = "/base/webmail/readmsg.php";
if(is_cgi_installed_ka(item:url, port:port)) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

# The attack is:
# http://YOURCOBALTBOX:444/base/webmail/readmsg.php?mailbox=../../../../../../../../../../../../../../etc/passwd&id=1
