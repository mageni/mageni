###############################################################################
# OpenVAS Vulnerability Test
# $Id: ircd_ratbox_37979.nasl 14233 2019-03-16 13:32:43Z mmartin $
#
# ircd-ratbox 'HELP' Command Denial Of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.100471");
  script_version("$Revision: 14233 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-16 14:32:43 +0100 (Sat, 16 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-01-28 18:48:47 +0100 (Thu, 28 Jan 2010)");
  script_bugtraq_id(37979);
  script_cve_id("CVE-2010-0300");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("ircd-ratbox 'HELP' Command Denial Of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37979");
  script_xref(name:"URL", value:"http://www.ircd-ratbox.org/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("ircd.nasl");
  script_require_ports("Services/irc", 6667);
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");
  script_tag(name:"summary", value:"The 'ircd-ratbox' daemon is prone to a denial-of-service
vulnerability.

Attackers can exploit this issue to deny service to legitimate users.

This issue affects ircd-ratbox 2.2.8. Other versions may also
be affected.");
  exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/irc");
if(!port)port = 6667;
if(! get_port_state(port)) exit(0);

banner = get_kb_item(string("irc/banner/", port));
if(!banner)exit(0);
if("ratbox" >!< banner)exit(0);

version = eregmatch(pattern:"ircd-ratbox-([0-9.]+)", string: banner);
if(isnull(version[1]))exit(0);

if(version_is_less_equal(version: version[1], test_version: "2.2.8")) {
  security_message(port:port);
  exit(0);
}

