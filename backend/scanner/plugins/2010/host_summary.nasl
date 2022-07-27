###############################################################################
# OpenVAS Vulnerability Test
# $Id: host_summary.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# Host Summary
#
# Authors:
# Michael Wiegand <michael.wiegand@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810003");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-08-10 14:49:09 +0200 (Tue, 10 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Host Summary");
  script_category(ACT_END);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secspace_traceroute.nasl", "secpod_open_tcp_ports.nasl");
  script_tag(name:"summary", value:"This KB summarizes technical information about the scanned host
collected during the scan.");
  exit(0);
}

report = "traceroute:";
route = get_kb_item("traceroute/route");
if (route)
{
  report += route;
}
report += '\n';

report += "TCP ports:";
ports = get_kb_item("Ports/open/tcp");
if (ports)
{
  report += ports;
}
report += '\n';

report += "UDP ports:";
ports = get_kb_item("Ports/open/udp");
if (ports)
{
  report += ports;
}
report += '\n';

log_message (proto: "HOST-T", data: report);
