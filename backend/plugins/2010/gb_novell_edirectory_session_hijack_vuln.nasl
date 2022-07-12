##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_edirectory_session_hijack_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Novell eDirectory 'DHOST' Cookie Hijack Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800731");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4655");
  script_name("Novell eDirectory 'DHOST' Cookie Hijack Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("novell_edirectory_detect.nasl");
  script_require_ports("Services/ldap", 389, 636);
  script_mandatory_keys("eDirectory/installed");

  script_xref(name:"URL", value:"http://www.metasploit.com/modules/auxiliary/admin/edirectory/edirectory_dhost_cookie");

  script_tag(name:"insight", value:"The flaw is due to error in an 'DHOST' module when handling DHOST web
  services. An attacker would wait until the real administrator logs in, then
  specify the predicted cookie value to hijack their session.");
  script_tag(name:"solution", value:"Apply the vendor provided patch.");
  script_tag(name:"summary", value:"This host is running Novell eDirectory is prone to Session Cookie
  hijack vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to hijack arbitrary
  sessions.");
  script_tag(name:"affected", value:"Novell eDirectory version 8.8.5 and prior.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.novell.com/support/kb/doc.php?id=3426981");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = make_list( "cpe:/a:novell:edirectory","cpe:/a:netiq:edirectory" );

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! major = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( ! sp = get_kb_item( "ldap/eDirectory/" + port + "/sp" ) )
  sp = "0";

reportver = major;

if( sp > 0 )
  reportver += ' SP' + sp;

edirVer = major + '.' + sp;

if(version_in_range(version:edirVer, test_version:"8.8", test_version2:"8.8.5")){
  report = report_fixed_ver( installed_version:reportver, fixed_version:"See advisory" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );