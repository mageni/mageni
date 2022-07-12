###############################################################################
# OpenVAS Vulnerability Test
# $Id: carello.nasl 11999 2018-10-21 09:01:06Z cfischer $
#
# Carello detection
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
#
# Date: Wed, 02 Oct 2002 17:10:21 +0100
# From: "Matt Moore" <matt@westpoint.ltd.uk>
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: wp-02-0012: Carello 1.3 Remote File Execution (Updated 1/10/2002)
#
# http://www.westpoint.ltd.uk/advisories/wp-02-0012.txt

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11776");
  script_version("$Revision: 11999 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-21 11:01:06 +0200 (Sun, 21 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2729);
  script_cve_id("CVE-2001-0614");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Carello detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to the latest version if necessary.");

  script_tag(name:"summary", value:"Carello.dll was found on your web server.
  Versions up to 1.3 of this web shopping cart allowed anybody
  to run arbitrary commands on your server.

  *** Note that no attack was performed, and the version number was

  *** not checked, so this might be a false alert");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

res = is_cgi_installed_ka( item:"Carello.dll", port:port );
if( res ) {
  security_message( port:port );
}

exit( 0 );