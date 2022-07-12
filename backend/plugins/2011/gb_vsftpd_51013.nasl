###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vsftpd_51013.nasl 12018 2018-10-22 13:31:29Z mmartin $
#
# vsftpd '__tzfile_read()' Function Heap Based Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = 'cpe:/a:beasts:vsftpd';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103362");
  script_bugtraq_id(51013);
  script_version("$Revision: 12018 $");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 15:31:29 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-13 10:23:55 +0100 (Tue, 13 Dec 2011)");
  script_name("vsftpd '__tzfile_read()' Function Heap Based Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("sw_vsftpd_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("vsftpd/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51013");
  script_xref(name:"URL", value:"http://dividead.wordpress.com/tag/heap-overflow/");
  script_xref(name:"URL", value:"https://security.appspot.com/vsftpd/Changelog.txt");
  script_xref(name:"URL", value:"https://security.appspot.com/vsftpd.html");

  script_tag(name:"summary", value:"vsftpd is prone to a buffer-overflow vulnerability because
  it fails to perform adequate boundary checks on user-supplied data.");

  script_tag(name:"impact", value:"Attackers may leverage this issue to execute arbitrary code in the
  context of the application. Failed attacks will cause denial-of-service conditions.");

  script_tag(name:"affected", value:"vsftpd 2.3.4 is affected. Other versions may also be vulnerable.");

  script_tag(name:"solution", value:"A fixed version 2.3.5 is available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_equal( version:vers, test_version:"2.3.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.3.5" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
