###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ipmi_no_auth_enabled.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# IPMI No Auth Access Mode Enabled
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.103837");
  script_version("$Revision: 11865 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-11-26 12:13:03 +0100 (Tue, 26 Nov 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("IPMI No Auth Access Mode Enabled");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("General");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_ipmi_detect.nasl");
  script_require_udp_ports("Services/udp/ipmi", 623);
  script_mandatory_keys("ipmi/no_auth_supported");

  script_tag(name:"solution", value:"Disable the 'No Auth' access mode.");
  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"summary", value:"The remote IPMI service has the 'No Auth' access mode enabled.");

  exit(0);
}

port = get_kb_item("Services/udp/ipmi");
if(!port)exit(0);

if(!get_udp_port_state(port))exit(0);

if(get_kb_item("ipmi/no_auth_supported")) {
  security_message(port:port, proto:"udp");
  exit(0);
}

exit(99);

