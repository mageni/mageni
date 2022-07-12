###############################################################################
# OpenVAS Vulnerability Test
# $Id: wsftp_classic_flaws.nasl 13613 2019-02-12 16:12:57Z cfischer $
#
# WS FTP server FTP bounce attack and PASV connection hijacking flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
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

#  Ref : Hobbit <hobbit@avian.org>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14599");
  script_version("$Revision: 13613 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 17:12:57 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(6050, 6051);
  script_cve_id("CVE-1999-0017");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WS FTP server FTP bounce attack and PASV connection hijacking flaw");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/ws_ftp/detected");

  script_tag(name:"summary", value:"According to its version number, the remote WS_FTP server is vulnerable
  to session hijacking during passive connections and to a FTP bounce attack when a user submits a specially
  crafted FTP command.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to the latest version of this software.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include ("ftp_func.inc");

port = get_ftp_port( default:21 );
if( ! banner = get_ftp_banner( port:port ) ) exit( 0 );
if( "WS_FTP Server" >!< banner ) exit( 0 );

if( egrep( pattern:"WS_FTP Server ([0-2]\.|3\.(0\.|1\.[0-3][^0-9]))", string:banner ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );