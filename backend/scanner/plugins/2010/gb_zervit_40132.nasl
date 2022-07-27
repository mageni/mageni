###############################################################################
# OpenVAS Vulnerability Test
#
# Zervit HTTP Server Source Code Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100637");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2010-05-14 12:04:31 +0200 (Fri, 14 May 2010)");
  script_bugtraq_id(40132);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Zervit HTTP Server Source Code Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40132");
  script_xref(name:"URL", value:"http://zervit.sourceforge.net/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Zervit/banner");

  script_tag(name:"summary", value:"Zervit is prone to a vulnerability that lets attackers access source
  code files.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to retrieve certain files
  from the vulnerable computer in the context of the webserver process.
  Information obtained may aid in further attacks.");

  script_tag(name:"affected", value:"Zervit 0.4 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(!banner || "Server: Zervit" >!< banner)
  exit(0);

version = eregmatch(pattern:"Server: Zervit ([0-9.]+)", string: banner);

if(isnull(version[1]))exit(0);
vers = version[1];

if(!isnull(vers)) {
  if(version_is_equal(version: vers, test_version: "0.4")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);