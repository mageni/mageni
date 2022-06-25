###############################################################################
# OpenVAS Vulnerability Test
# $Id: rsync_path_sanitation_vuln.nasl 9348 2018-04-06 07:01:19Z cfischer $
#
# rsync path sanitation vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14223");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(10938);
  script_cve_id("CVE-2004-0792");
  script_name("rsync path sanitation vulnerability");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_category(ACT_GATHER_INFO);
  script_family("Gain a shell remotely");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_dependencies("rsync_modules.nasl");
  script_require_ports("Services/rsync", 873);

  script_tag(name:"summary", value:"A vulnerability has been reported in rsync, which potentially can be exploited
  by malicious users to read or write arbitrary files on a vulnerable system.");

  script_tag(name:"impact", value:"There is a flaw in this version of rsync which, due to an input validation
  error, would allow a remote attacker to gain access to the remote system.");

  script_tag(name:"insight", value:"An attacker, exploiting this flaw, would need network access to the TCP port.

  Successful exploitation requires that the rsync daemon is *not* running chrooted.");

  script_tag(name:"solution", value:"Upgrade to rsync 2.6.3 or newer.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("rsync_func.inc");

port = get_rsync_port( default:873 );

welcome = get_kb_item( "rsync/" + port + "/banner" );
if ( ! welcome ) {
  soc = open_sock_tcp( port );
  if( ! soc ) exit( 0 );
  welcome = recv_line( socket:soc, length:4096 );
  if( ! welcome ) exit( 0 );
}

# rsyncd speaking protocol 28 are not vulnerable
if( ereg( pattern:"@RSYNCD: (1[0-9]|2[0-8])", string:welcome ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );