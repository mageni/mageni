# OpenVAS Vulnerability Test
# $Id: codered_x.nasl 13685 2019-02-15 10:06:52Z cfischer $
# Description: CodeRed version X detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10713");
  script_version("$Revision: 13685 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 11:06:52 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2880);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2001-0500");
  script_name("CodeRed version X detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("This script is Copyright (C) 2001 SecuriTeam");
  script_family("Malware");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/banner");

  script_tag(name:"solution", value:"1) Remove the file root.exe from both directories:

  \inetpub\scripts

  and

  \program files\common files\system\msadc

  2) Install an updated antivirus program (this will remove the Explorer.exe Trojan)

  3) Set SFCDisable in hklm\software\microsoft\windows nt\currentversion\winlogon to: 0

  4) Remove the two newly created virtual directories: C and D (Created by the Trojan)

  5) Make sure no other files have been modified.

  It is recommended that hosts that have been compromised by Code Red X would reinstall the operating system from scratch and patch it accordingly.");

  script_xref(name:"URL", value:"http://www.securiteam.com/securitynews/5GP0V004UQ.html");
  script_xref(name:"URL", value:"http://www.securiteam.com/windowsntfocus/5WP0L004US.html");
  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-2001-11.html");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/itsolutions/security/tools/redfix.asp");

  script_tag(name:"summary", value:"Your machine is infected with the 'Code Red' worm. Your Windows system seems to be compromised.");

  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
if( http_get_is_marked_embedded( port:port ) )
  exit( 0 );

sig = get_http_banner(port:port);
if( !sig || "IIS" >!< sig )
  exit(0);

soc = http_open_socket(port);
if(!soc)
  exit(0);

req = http_get(item:"/scripts/root.exe?/c+dir+c:\+/OG", port:port);
send(socket:soc, data:req);
buf = http_recv(socket:soc);
http_close_socket(soc);

pat1 = "<DIR>";
pat2 = "Directory of C";

if ( ("This program cannot be run in DOS mode" >< buf) || (pat1 >< buf) || (pat2 >< buf) )
{
  security_message(port);
  exit(0);
} else {

  soc = http_open_socket(port);
  if ( ! soc )
    exit(0);

  req = http_get(item:"/c/winnt/system32/cmd.exe?/c+dir+c:\+/OG", port:port);
  send(socket:soc, data:req);

  buf = http_recv(socket:soc);
  http_close_socket(soc);

  if (("This program cannot be run in DOS mode" >< buf) || (pat1 >< buf) || (pat2 >< buf) )
  {
    security_message(port);
    exit(0);
  }
}