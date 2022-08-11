###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ssh_weak_hmac.nasl 13581 2019-02-11 14:32:32Z cfischer $
#
# SSH Weak MAC Algorithms Supported
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105610");
  script_version("$Revision: 13581 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 15:32:32 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-04-19 11:49:32 +0200 (Tue, 19 Apr 2016)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_tag(name:"cvss_base", value:"2.6");
  script_name("SSH Weak MAC Algorithms Supported");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_ssh_algos.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/algos_available");

  script_tag(name:"summary", value:"The remote SSH server is configured to allow weak MD5 and/or 96-bit MAC algorithms.");

  script_tag(name:"solution", value:"Disable the weak MAC algorithms.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("ssh_func.inc");

function check_algo( port, type ) {

  local_var macs, port, type;

  if( ! type || ! port )
    return;

  algos = get_kb_list( "ssh/" + port + "/mac_algorithms_" + type );
  if( ! algos )
    return;

  macs = '';

  # Sort to not report changes on delta reports if just the order is different
  algos = sort( algos );

  foreach found_algo( algos )
    if( "none" >< found_algo || "md5" >< found_algo || "-96" >< found_algo )
      macs += found_algo + '\n';

  if( strlen( macs ) > 0 )
    return macs;
}

port = get_ssh_port( default:22 );

if( rep = check_algo( port:port, type:"client_to_server" ) )
  report = 'The following weak client-to-server MAC algorithms are supported by the remote service:\n\n' + rep + '\n\n';

if( rep = check_algo( port:port, type:"server_to_client" ) )
  report += 'The following weak server-to-client MAC algorithms are supported by the remote service:\n\n' + rep + '\n\n';

if( report ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );