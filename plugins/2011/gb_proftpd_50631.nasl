###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_proftpd_50631.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# ProFTPD Prior To 1.3.3g Use-After-Free Remote Code Execution Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:proftpd:proftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103331");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-15 10:15:56 +0100 (Tue, 15 Nov 2011)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2011-4130");
  script_bugtraq_id(50631);
  script_name("ProFTPD Prior To 1.3.3g Use-After-Free Remote Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("secpod_proftpd_server_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ProFTPD/Installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50631");
  script_xref(name:"URL", value:"http://bugs.proftpd.org/show_bug.cgi?id=3711");
  script_xref(name:"URL", value:"http://www.proftpd.org");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-328/");

  script_tag(name:"summary", value:"ProFTPD is prone to a remote code-execution vulnerability.");
  script_tag(name:"affected", value:"ProFTPD prior to 1.3.3g are vulnerable.");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"impact", value:"Successful exploits will allow attackers to execute arbitrary code
  within the context of the application. Failed exploit attempts will
  result in a denial-of-service condition.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"1.3.3g" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.3.3g" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );