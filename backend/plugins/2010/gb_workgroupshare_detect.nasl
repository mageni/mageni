###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_workgroupshare_detect.nasl 14233 2019-03-16 13:32:43Z mmartin $
#
# WorkgroupShare Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.100518");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 14233 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-16 14:32:43 +0100 (Sat, 16 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-03-05 14:01:46 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("WorkgroupShare Detection");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "find_service1.nasl");
  script_require_ports("Services/WorkgroupShare", 8100);
  script_tag(name:"summary", value:"This host is running a WorkgroupShare Server. WorkgroupShare lets the
people share their personal Outlook folders, such as calendar,
contact, task and notes information by using standard internet
protocols.");
  exit(0);
}

port = get_kb_item("Services/WorkgroupShare");
if(!port)port = 8100;

if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);

if(!soc)exit(0);
send(socket:soc, data:"\n");
buf = recv(socket:soc, length:512);
if( buf == NULL )exit(0);

if("OK WorkgroupShare" >< buf) {

  version = eregmatch(pattern: "WorkgroupShare ([0-9.]+)", string:buf);

  if(!isnull(version[1])) {
    ver = version[1];
    info = string("\n\nWorkgroupShare version '", ver,"' was found on the remote Host.\n");
    log_message(port:port, data:info);
  }  else {
    log_message(port:port);
  }
}

exit(0);
