###############################################################################
# OpenVAS Vulnerability Test
# $Id: microsoft-iis-nlst-stack-overflow.nasl 13613 2019-02-12 16:12:57Z cfischer $
#
# Microsoft IIS FTPd NLST stack overflow
#
# Authors:
# Tim Brown <timb@openvas.org>
#
# Copyright:
# Copyright (c) 2009 Tim Brown
# Text descriptions are largerly excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.100952");
  script_version("$Revision: 13613 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 17:12:57 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-09-02 01:41:39 +0200 (Wed, 02 Sep 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3023");
  script_name("Microsoft IIS FTPd NLST stack overflow");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("(c) Tim Brown, 2009");
  script_dependencies("ftp_writeable_directories.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/microsoft/iis_ftp/detected", "ftp/writeable_dir");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36189");

  script_tag(name:"summary", value:"Microsoft IIS FTPd NLST stack overflow

  The Microsoft IIS FTPd service may be vulnerable to a stack overflow via the NLST command. On Microsoft IIS 5.x this vulnerability
  can be used to gain remote SYSTEM level access, whilst on IIS 6.x it has been reported to result in a denial of service. Whilst it
  can be triggered by authenticated users with write access to the FTP server, this check determines whether anonymous users have the
  write access necessary to trigger it without authentication.");
  script_tag(name:"solution", value:"We are not aware of a vendor approved solution at the current time.

  On the following platforms, we recommend you mitigate in the described manner:

  Microsoft IIS 5.x

  Microsoft IIS 6.x

  We recommend you mitigate in the following manner:
  Filter inbound traffic to 21/tcp to only known management hosts
  Consider removing directories writable by 'anonymous'");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include ("ftp_func.inc");

port = get_ftp_port( default:21 );
if( ! banner = get_ftp_banner( port:port ) ) exit( 0 );

if( ! get_kb_item("ftp/writeable_dir" ) ) exit( 0 );

if( "Microsoft FTP Service" >< banner ) {
  if( "Version 5.0" >< banner || "Version 5.1" >< banner ) {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );