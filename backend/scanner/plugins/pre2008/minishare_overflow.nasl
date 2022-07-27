###############################################################################
# OpenVAS Vulnerability Test
#
# MiniShare webserver buffer overflow
#
# Authors:
# Gareth Phillips - SensePost PTY ltd (www.sensepost.com)
# Changes by Tenable Network Security :
# * detect title to prevent false positives
# * fix version detection
# * added CVE and OSVDB xrefs.
#
# Copyright:
# Copyright (C) 2005 SensePost
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
  script_oid("1.3.6.1.4.1.25623.1.0.18424");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2271");
  script_bugtraq_id(11620);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("MiniShare webserver buffer overflow");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 SensePost");
  script_family("Gain a shell remotely");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"MiniShare 1.4.1 and prior versions are affected by a buffer overflow flaw.");

  script_tag(name:"impact", value:"A remote attacker could execute arbitrary commands by sending a specially
  crafted file name in a the GET request.");

  script_tag(name:"affected", value:"Version 1.3.4 and below do not seem to be vulnerable.");

  script_tag(name:"solution", value:"Upgrade to MiniShare 1.4.2 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

res = http_get_cache( item:"/", port:port );
if(!res || "<title>MiniShare</title>" >!< res)
  exit( 0 );

if( egrep( string:res, pattern:'<p class="versioninfo"><a href="http://minishare\\.sourceforge\\.net/">MiniShare 1\\.(3\\.([4-9][^0-9]|[0-9][0-9])|4\\.[0-1][^0-9])' ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );