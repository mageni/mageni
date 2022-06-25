###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vsftpd_72451.nasl 5026 2017-01-18 09:59:52Z cfi $
#
# vsftpd < 3.0.3 Security Bypass Vulnerability
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108045");
  script_bugtraq_id(72451);
  script_cve_id("CVE-2015-1419");
  script_version("$Revision: 5026 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-01-18 10:59:52 +0100 (Wed, 18 Jan 2017) $");
  script_tag(name:"creation_date", value:"2017-01-18 10:23:55 +0100 (Wed, 18 Jan 2017)");
  script_name("vsftpd < 3.0.3 Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("sw_vsftpd_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("vsftpd/installed");

  script_xref(name:"URL", value:"https://security.appspot.com/vsftpd/Changelog.txt");
  script_xref(name:"URL", value:"https://security.appspot.com/vsftpd.html");

  script_tag(name:"summary", value:"The vsftp daemon was not handling the deny_file option properly, allowing unauthorized access in some specific scenarios");

  script_tag(name:"impact", value:"An attacker can exploit this issue to bypass certain
  security restrictions and perform unauthorized actions. This may aid in further attacks.");

  script_tag(name:"affected", value:"vsftpd versions 3.0.2 and below are vulnerable.");

  script_tag(name:"solution", value:"A fixed version 3.0.3 is available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"3.0.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );