###############################################################################
# OpenVAS Vulnerability Test
# $Id: servit_0_0_3.nasl 13685 2019-02-15 10:06:52Z cfischer $
#
# Zervit HTTP Server Malformed URI Remote Denial Of Service Vulnerability
#
# Authors
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100167");
  script_version("$Revision: 13685 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 11:06:52 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-04-26 20:59:36 +0200 (Sun, 26 Apr 2009)");
  script_bugtraq_id(34637);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Zervit HTTP Server Malformed URI Remote Denial Of Service Vulnerability");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Zervit/banner");

  script_tag(name:"summary", value:"According to its version number, the remote version of Zervit HTTP
  server is prone to a denial-of-service vulnerability because it fails to adequately sanitize user-supplied input.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to crash the affected application,
  denying service to legitimate users.");

  script_tag(name:"affected", value:"Zervit 0.3 is vulnerable. Other versions may also be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34637");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if(!banner || !egrep(pattern:"Server: Zervit ([0-9.]+)", string:banner) )
  exit(0);

version = eregmatch(pattern: "Zervit ([0-9.]+)", string: banner);
if(version[1] == "0.3") {
  security_message(port:port);
  exit(0);
}

exit(99);