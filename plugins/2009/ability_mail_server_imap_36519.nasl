###############################################################################
# OpenVAS Vulnerability Test
# $Id: ability_mail_server_imap_36519.nasl 13409 2019-02-01 13:13:33Z cfischer $
#
# Code-Crafters Ability Mail Server IMAP FETCH Request Remote Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100298");
  script_version("$Revision: 13409 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-01 14:13:33 +0100 (Fri, 01 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-10-10 11:30:08 +0200 (Sat, 10 Oct 2009)");
  script_bugtraq_id(36519);
  script_cve_id("CVE-2009-3445");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Code-Crafters Ability Mail Server IMAP FETCH Request Remote Denial Of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("imap4_banner.nasl");
  script_require_ports("Services/imap", 143);
  script_mandatory_keys("imap/codecrafters/ability/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36519");
  script_xref(name:"URL", value:"http://www.code-crafters.com/abilitymailserver/index.html");
  script_xref(name:"URL", value:"http://www.code-crafters.com/abilitymailserver/updatelog.html");

  script_tag(name:"impact", value:"Attackers can exploit this issue to cause the affected application to
  crash, denying service to legitimate users.");

  script_tag(name:"affected", value:"Versions prior to Ability Mail Server 2.70 are affected.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"Ability Mail Server is prone to a denial-of-service vulnerability
  because it fails to adequately handle IMAP requests.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("imap_func.inc");
include("version_func.inc");

port = get_imap_port( default:143 );

if( ! banner = get_imap_banner( port:port ) ) exit( 0 );
if( "Code-Crafters" >!< banner ) exit( 0 );

version = eregmatch( pattern:"Ability Mail Server ([0-9.]+)", string:banner );
if( isnull( version[1] ) ) exit( 0 );

if( version_is_less( version:version[1], test_version:"2.70" ) ) {
  report = report_fixed_ver( installed_version:version[1], fixed_version:"2.70" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );