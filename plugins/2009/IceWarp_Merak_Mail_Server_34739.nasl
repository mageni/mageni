###############################################################################
# OpenVAS Vulnerability Test
# $Id: IceWarp_Merak_Mail_Server_34739.nasl 14330 2019-03-19 13:59:11Z asteins $
#
# IceWarp Merak Mail Server 'Base64FileEncode()' Stack-Based Buffer Overflow Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:icewarp:mail_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100168");
  script_version("$Revision: 14330 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:59:11 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1516");
  script_bugtraq_id(34739);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_name("IceWarp Merak Mail Server 'Base64FileEncode()' Stack-Based Buffer Overflow Vulnerability");
  script_family("Web application abuses");
  script_dependencies("gb_icewarp_web_detect.nasl");
  script_mandatory_keys("icewarp/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34739");

  script_tag(name:"summary", value:"IceWarp Merak Mail Server is prone to a stack-based buffer-overflow
  vulnerability because the application fails to bounds-check user-supplied data before
  copying it into an insufficiently sized buffer.");

  script_tag(name:"impact", value:"An attacker could exploit this issue to execute arbitrary code in
  the context of the affected application. Failed exploit attempts will likely result in
  denial-of-service conditions.");

  script_tag(name:"affected", value:"IceWarp Merak Mail Server 9.4.1 is vulnerable, other versions may
  also be affected.");

  script_tag(name:"solution", value:"Upgrade to Merak Mail Server 9.4.2");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less_equal( version:vers, test_version:"9.4.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"9.4.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
