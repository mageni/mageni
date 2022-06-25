###############################################################################
# OpenVAS Vulnerability Test
# $Id: lcdproc_buffer_overflow.nasl 11723 2018-10-02 09:59:19Z ckuersteiner $
#
# LCDproc buffer overflow
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2000 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10378");
  script_version("$Revision: 11723 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-02 11:59:19 +0200 (Tue, 02 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1131);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2000-0295");

  script_name("LCDproc buffer overflow");

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("This script is Copyright (C) 2000 SecuriTeam");
  script_family("Buffer overflow");
  script_dependencies("lcdproc_detect.nasl");
  script_require_ports("Services/lcdproc", 13666);
  script_mandatory_keys("lcdproc/detected");

  script_tag(name:"solution", value:"Disable access to this service from outside by disabling access to TCP port
13666 (default port used)");

  script_tag(name:"summary", value:"LCDproc is a system that is used to display system information and other data
  on an LCD display (or any supported display
  device, including curses or text) The LCDproc version 4.0 and above uses a client-server
  protocol, allowing anyone with access to the LCDproc server to modify the displayed content.
  It is possible to cause the LCDproc server to crash and execute arbitrary code by sending
  the server a large buffer that will overflow its internal buffer.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

port = get_kb_item( "Services/lcdproc" );
if( ! port ) port = 13666;

if( get_port_state( port ) ) {
  soc = open_sock_tcp( port );
  if( ! soc ) exit( 0 );
  result = recv_line( socket:soc, length:4096 );
  close( soc );
  if( ! result ) exit(0);

  req = crap( 4096 );
  soc = open_sock_tcp( port );
  if( soc ) {
    send( socket:soc, data:req );
    result = recv( socket:soc, length:4096 );
    if( strlen( result ) == 0 ) {
      security_message( port:port );
      exit( 0 );
    }
    close( soc );
  }
}

exit( 0 );
