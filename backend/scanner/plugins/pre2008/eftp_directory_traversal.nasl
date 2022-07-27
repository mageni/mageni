###############################################################################
# OpenVAS Vulnerability Test
# $Id: eftp_directory_traversal.nasl 13613 2019-02-12 16:12:57Z cfischer $
#
# EFTP tells if a given file exists
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# starting from guild_ftp.nasl
#
# Copyright:
# Copyright (C) 2001 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.10933");
  script_version("$Revision: 13613 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 17:12:57 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3333);
  script_cve_id("CVE-2001-1109");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("EFTP tells if a given file exists");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2001 Michel Arboi");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/eftp/detected");

  script_tag(name:"summary", value:"The remote FTP server can be used to determine if a given
  file exists on the remote host or not, by adding dot-dot-slashes in front of them.");

  script_tag(name:"insight", value:"For instance, it is possible to determine the presence
  of \autoexec.bat by using the command SIZE or MDTM on ../../../../autoexec.bat");

  script_tag(name:"impact", value:"An attacker may use this flaw to gain more knowledge about
  this host, such as its file layout. This flaw is specially useful when used with other vulnerabilities.");

  script_tag(name:"solution", value:"Update your EFTP server to 2.0.8.348 or change it.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");

cmd[0] = "SIZE";
cmd[1] = "MDTM";

kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
pass = kb_creds["pass"];

port = get_ftp_port( default:21 );
banner = get_ftp_banner( port:port );
if( ! banner || "EFTP " >!< banner )
  exit( 0 );

vuln = 0;

soc = open_sock_tcp( port );
if( soc ) {

  if( login && ftp_authenticate( socket:soc, user:login, pass:pass ) ) {
    for( i = 0; cmd[i]; i = i + 1 ) {
      req = string( cmd[i], " ../../../../../../autoexec.bat\r\n" );
      send(socket:soc, data:req);
      r = ftp_recv_line( socket:soc );
      if( "230 " >< r ) vuln = vuln + 1;
    }
  } else {
    # We could not log in or could not download autoexec.
    # We'll just attempt to grab the banner and check for version
    # <= 2.0.7
    # I suppose that any version < 2 is vulnerable...
    r = ftp_recv_line( socket:soc );
    if( egrep( string:r, pattern:".*EFTP version ([01]|2\.0\.[0-7])\..*" ) ) {
      vuln = 1;
    }
  }
  close( soc );
  if( vuln ) {
    security_message(port:port);
    exit(0);
  }
  exit(99);
}

#
# NB: This server is also vulnerable to another attack.
#
# Date:  Thu, 13 Dec 2001 12:59:43 +0200
# From: "Ertan Kurt" <ertank@olympos.org>
# Affiliation: Olympos Security
# To: bugtraq@securityfocus.com
# Subject: EFTP 2.0.8.346 directory content disclosure
#
# It is possible to see the contents of every drive and directory of
# vulnerable server.
# A valid user account is required to exploit this vulnerability.
# It works both with encryption and w/o encryption.
# Here's how it's done:
# the user is logged in to his home directory (let's say d:\userdir)
# when the user issues a CWD to another directory server returns
# permission denied.
# But, first changing directory to "..." (it will chdir to d:\userdir\...)
# then issuing a CWD to "\" will say permission denied but it will
# successfully change to root directory of the current drive.
# And every time we want to see a dir's content, we first CWD to our
# home directory and then CWD ...  and then CWD directly to desired
# directory (CWD c:/ or c:/winnt etc)
#
# So it is possible to see directory contents but i did not test to see
# if there is a possible way to get/put files.
#