# OpenVAS Vulnerability Test
# Description: Kuang2 the Virus
#
# Authors:
# Scott Adkins <sadkins@cns.ohiou.edu>
#
# Copyright:
# Copyright (C) 2000 Scott Adkins
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10132");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Kuang2 the Virus");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 Scott Adkins");
  script_family("Malware");
  script_dependencies("find_service.nasl");
  script_require_ports(17300);

  script_xref(name:"URL", value:"http://vil.mcafee.com/dispVirus.asp?virus_k=10213");

  script_tag(name:"solution", value:"Disinfect the computer with the latest copy of virus scanning software.
  Alternatively, you can find a copy of the virus itself on the net by doing an Altavista search.
  The virus comes with the server, client and infector programs. The client program not only allows you to
  remotely control infected machines, but disinfect the machine the client is running on.");

  script_tag(name:"summary", value:"Kuang2 the Virus was found.");

  script_tag(name:"insight", value:"Kuang2 the Virus is a program that infects all the executables on the system,
  as well as set up a server that allows the remote control of the computer. The client program allows files to be
  browsed, uploaded, downloaded, hidden, etc on the infected machine. The client program also can execute programs
  on the remote machine.

  Kuang2 the Virus also has plugins that can be used that allows the client to do things to the remote machine, such
  as hide the icons and start menu, invert the desktop, pop up message windows, etc.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

port = 17300;
if(!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

data = recv_line(socket:soc, length:100);
close(soc);
if(!data)
  exit(0);

if("YOK2" >< data) {
  security_message(port:port);
  exit(0);
}

exit(99);