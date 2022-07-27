###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_golden_ftp_45924.nasl 13510 2019-02-06 16:00:24Z cfischer $
#
# Golden FTP Server Malformed Message Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103037");
  script_version("$Revision: 13510 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 17:00:24 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-01-20 13:02:23 +0100 (Thu, 20 Jan 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-6576");
  script_bugtraq_id(45924);
  script_name("Golden FTP Server Malformed Message Denial Of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/golden_tfp/detected");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/45924");
  script_xref(name:"URL", value:"http://www.mediafire.com/?jej19gc93zjbiyu");

  script_tag(name:"summary", value:"Golden FTP Server is prone to a denial-of-service vulnerability.");

  script_tag(name:"impact", value:"Exploits will cause the application to crash, denying service to
  legitimate users.");

  script_tag(name:"affected", value:"Golden FTP Server 4.70 is vulnerable. Other versions may also
  be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("version_func.inc");

port = get_ftp_port( default:21 );
banner = get_ftp_banner( port:port );
if( ! banner || "Golden FTP" >!< banner )
  exit( 0 );

version = eregmatch( pattern:"Golden FTP Server ready v([0-9.]+)", string:banner );

if( ! isnull( version[1] ) ) {
  if( version_is_less_equal( version:version[1], test_version:"4.70" ) ) {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );