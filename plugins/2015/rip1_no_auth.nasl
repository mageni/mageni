###############################################################################
# OpenVAS Vulnerability Test
# $Id: rip1_no_auth.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# RIP-1 Poisoning Routing Table
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.105236");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11872 $");

  script_name("RIP-1 Poisoning Routing Table");

  script_tag(name:"impact", value:"Attackers can exploit this issue to obtain sensitive information that
 may lead to further attacks.");

  script_tag(name:"vuldetect", value:"Send a RIP request and check the response");
  script_tag(name:"insight", value:"RIP-1 does not implement authentication.
An attacker may feed your machine with bogus routes and hijack network connection");

  script_tag(name:"solution", value:"Disable the RIP agent if you don't use it, or use
RIP-2 and implement authentication'");

  script_tag(name:"summary", value:"This host is running a RIP-1 agent.");
  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-03-13 09:16:37 +0100 (Fri, 13 Mar 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("rip_detect.nasl");
  script_require_udp_ports("Services/udp/rip", 520);
  script_mandatory_keys("RIP-1/enabled");

  exit(0);
}

port = get_kb_item("Services/udp/rip");
if( ! port ) exit( 0 );

if( get_kb_item("RIP-1/enabled") )
{
  security_message( port:port, proto:'udp');
  exit( 0 );
}

exit( 99 );
