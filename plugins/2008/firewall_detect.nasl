###############################################################################
# OpenVAS Vulnerability Test
# $Id: firewall_detect.nasl 14240 2019-03-17 15:50:45Z cfischer $
#
# Firewall Enabled
#
# Authors:
# Tenable Network Security, Inc. based on work by Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2007 Tenable Network Security / Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.80059");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Firewall Enabled");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2007 Tenable Network Security / Michel Arboi");
  script_family("Firewalls");
  script_mandatory_keys("Host/scanners/openvas_tcp_scanner"); # This plugin only works if openvas_tcp_scanner has run

  script_tag(name:"summary", value:"Based on the responses obtained by the TCP scanner, it was possible to
  determine that the remote host seems to be protected by a firewall.

  Important: This plugin only works if OpenVAS TCP Scanner was used.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

if ( ! get_kb_item("Host/scanners/openvas_tcp_scanner") )
  exit(0); # This plugin only works if openvas_tcp_scanner has run

open = int(get_kb_item("TCPScanner/OpenPortsNb"));
closed = int(get_kb_item("TCPScanner/ClosedPortsNb"));
filtered = int(get_kb_item("TCPScanner/FilteredPortsNb"));

total = open + closed + filtered;

if (total == 0) exit(0);
if (filtered == 0 ) exit(0);
if ( get_kb_item("TCPScanner/RSTRateLimit") ) exit(0);

if ( filtered > ( closed * 4 ) )
{
  log_message(port:0);
  set_kb_item(name:"Host/firewalled", value:TRUE);
}
