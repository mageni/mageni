# OpenVAS Vulnerability Test
# $Id: vpasswd_cgi.nasl 14336 2019-03-19 14:53:10Z mmartin $
# Description: vpasswd.cgi
#
# Authors:
# Michel Arboi
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

# References
# Date: Thu, 24 Oct 2002 10:41:48 -0700 (PDT)
# From:"Jeremy C. Reed" <reed@reedmedia.net>
# To:bugtraq@securityfocus.com
# Subject: Re: vpopmail CGIapps vpasswd vulnerabilities
# In-Reply-To: <200210241126.33510.n.bugtraq@icana.org.ar>
# Message-ID: <Pine.LNX.4.43.0210241020040.25224-100000@pilchuck.reedmedia.net>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11165");
  script_version("$Revision: 14336 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:53:10 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(6038);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("vpasswd.cgi");
  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"solution", value:"Remove it from /cgi-bin.");
  script_tag(name:"summary", value:"The 'vpasswd.cgi' CGI is installed. Some versions
do not properly check for special characters and allow
a cracker to execute any command on your system.

*** Warning : The scanner relied on the presence of this CGI, it did not
*** determine if you specific version is vulnerable to that problem");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

res = is_cgi_installed_ka(item:"vpasswd.cgi", port:port);
if(res)security_message(port);
