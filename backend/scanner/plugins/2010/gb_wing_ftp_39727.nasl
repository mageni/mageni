###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wing_ftp_39727.nasl 13613 2019-02-12 16:12:57Z cfischer $
#
# Wing FTP Server Versions Prior to 3.4.1 Multiple Information Disclosure Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100611");
  script_version("$Revision: 13613 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 17:12:57 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-04-28 14:05:27 +0200 (Wed, 28 Apr 2010)");
  script_bugtraq_id(39727);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("Wing FTP Server Versions Prior to 3.4.1 Multiple Information Disclosure Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/wing/ftp/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39727");
  script_xref(name:"URL", value:"http://www.wftpserver.com/");
  script_xref(name:"URL", value:"http://www.wftpserver.com/serverhistory.htm");

  script_tag(name:"summary", value:"Wing FTP Server is prone to multiple information-disclosure
  vulnerabilities.");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to gain access to sensitive
  information that may lead to further attacks.");

  script_tag(name:"affected", value:"Versions prior to Wing FTP Server 3.4.1 are vulnerable.");

  script_tag(name:"solution", value:"The vendor released an update. Please see the references for more
  information.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");
include("version_func.inc");

port = get_ftp_port( default:21 );
if( ! banner = get_ftp_banner( port:port ) ) exit( 0 );
if( "220 Wing FTP Server" >!< banner ) exit( 0 );

version = eregmatch( pattern:"Wing FTP Server ([^ ]+) ready", string:banner );

if( ! isnull( version[1] ) ) {
  if( version_is_less( version:version[1], test_version:"3.4.1" ) ) {
    report = report_fixed_ver( installed_version:version[1], fixed_version:"3.4.1" );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );