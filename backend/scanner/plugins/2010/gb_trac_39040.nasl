###############################################################################
# OpenVAS Vulnerability Test
#
# Trac Ticket Validation Security Bypass Vulnerability
#
# Authors:
# Michael Meyer
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
  script_oid("1.3.6.1.4.1.25623.1.0.100563");
  script_version("2019-05-14T08:13:05+0000");
  script_tag(name:"last_modification", value:"2019-05-14 08:13:05 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-03-31 12:56:41 +0200 (Wed, 31 Mar 2010)");
  script_bugtraq_id(39040);

  script_name("Trac Ticket Validation Security Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39040");
  script_xref(name:"URL", value:"http://trac.edgewall.org/wiki/ChangeLog#a0.11.7");
  script_xref(name:"URL", value:"http://trac.edgewall.org/");

  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8000);
  script_mandatory_keys("tracd/banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the references
  for details.");

  script_tag(name:"summary", value:"Trac is prone to a security-bypass vulnerability.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to bypass certain security
  restrictions and perform unauthorized actions.");

  script_tag(name:"affected", value:"Versions prior to Trac 0.11.7 are vulnerable.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:8000);

banner = get_http_banner(port: port);
if(!banner || "Server: tracd/" >!< banner)
  exit(0);

version = eregmatch(pattern: "tracd/([0-9.]+)", string: banner);
if(isnull(version[1]))
  exit(0);

vers = version[1];

if(!isnull(vers)) {
  if(version_is_less(version: vers, test_version: "0.11.7")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);