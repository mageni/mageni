# OpenVAS Vulnerability Test
# $Id: Black_JumboDog_FTP_overflow.nasl 13613 2019-02-12 16:12:57Z cfischer $
# Description: BlackJumboDog FTP server multiple command overflow
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14256");
  script_version("$Revision: 13613 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 17:12:57 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1439");
  script_bugtraq_id(10834);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("BlackJumboDog FTP server multiple command overflow");
  script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/blackjumbodog/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to version 3.6.2 or newer.");

  script_tag(name:"summary", value:"The remote host is running BlackJumboDog FTP server.

  This FTP server fails to properly check the length of parameters
  in multiple FTP commands, most significant of which is USER, resulting in a stack overflow.");

  script_tag(name:"impact", value:"With a specially crafted request, an attacker can execute arbitrary code
  resulting in a loss of integrity, and/or availability.");

  exit(0);
}

include("ftp_func.inc");

port = get_ftp_port(default:21);
banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);

#220 FTP ( BlackJumboDog(-RAS) Version 3.6.1 ) ready
#220 FTP ( BlackJumboDog Version 3.6.1 ) ready

if( "BlackJumboDog" >< banner )
{
  if (safe_checks())
  {
    if ( egrep(pattern:"^220 .*BlackJumboDog.* Version 3\.([0-5]\.[0-9]+|6\.[01])", string:banner ) )
      security_message(port);
  }
  else
  {
    req1 = string("USER ", crap(300), "\r\n");
    soc=open_sock_tcp(port);
    if ( ! soc ) exit(0);
    send(socket:soc, data:req1);
    close(soc);
    sleep(1);
    soc2 = open_sock_tcp(port);
    if (! soc2 || ! ftp_recv_line(socket:soc))
    {
      security_message(port);
    }
    else
      close(soc2);
    exit(0);
  }
}
