###############################################################################
# OpenVAS Vulnerability Test
#
# Sambar sendmail /session/sendmail
#
# Authors:
# Hendrik Scholz <hendrik@scholz.net>
#
# Copyright:
# Copyright (C) 2000 by Hendrik Scholz <hendrik@scholz.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.10415");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"1.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:P/A:N");
  script_name("Sambar sendmail /session/sendmail");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 Hendrik Scholz");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/sambar");

  script_tag(name:"solution", value:"Try to disable this module. There might be a patch in the future.");

  script_tag(name:"summary", value:"The Sambar webserver is running. It provides a web interface for sending emails.
  You may simply pass a POST request to /session/sendmail and by this send mails to anyone you want.
  Due to the fact that Sambar does not check HTTP referrers you do not need direct access to the server!");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

url = "/session/sendmail";
if( is_cgi_installed_ka( port:port, item:url ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );