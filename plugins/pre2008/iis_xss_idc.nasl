###############################################################################
# OpenVAS Vulnerability Test
# $Id: iis_xss_idc.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# IIS XSS via IDC error
#
# Authors:
# Geoffroy Raimbault <graimbault@lynx-technologies.com>
# www.lynx-technologies.com
#
# Copyright:
# Copyright (C) 2002 Geoffroy Raimbault/Lynx Technologies
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
  script_oid("1.3.6.1.4.1.25623.1.0.11142");
  script_version("$Revision: 13679 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(5900);
  script_name("IIS XSS via IDC error");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("This script is Copyright (C) 2002 Geoffroy Raimbault/Lynx Technologies");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "cross_site_scripting.nasl");
  script_mandatory_keys("IIS/banner");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://online.securityfocus.com/bid/5900");
  script_xref(name:"URL", value:"http://www.ntbugtraq.com/default.asp?pid=36&sid=1&A2=ind0210&L=ntbugtraq&F=P&S=&P=1391");
  script_tag(name:"summary", value:"This IIS Server appears to be vulnerable to a Cross
Site Scripting due to an error in the handling of overlong requests on
an idc file. It is possible to inject Javascript
in the URL, that will appear in the resulting page.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
 of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
 disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

sig = get_http_banner(port:port);
if ( sig && "Server: Microsoft/IIS" >!< sig ) exit(0);
host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

# We construct the malicious URL with an overlong idc filename
filename = string("/<script></script>",crap(334),".idc");
req = http_get(item:filename, port:port);

r = http_keepalive_send_recv(port:port, data:req);
str="<script></script>";
if((r =~ "^HTTP/1\.[01] 200" && str >< r)) security_message(port);
