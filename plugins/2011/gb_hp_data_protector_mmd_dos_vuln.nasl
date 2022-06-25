###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_data_protector_mmd_dos_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# HP (OpenView Storage) Data Protector Media Management Daemon Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:hp:data_protector";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801963");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-10 13:49:51 +0200 (Wed, 10 Aug 2011)");
  script_cve_id("CVE-2011-2399");
  script_bugtraq_id(48917);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("HP (OpenView Storage) Data Protector Media Management Daemon Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("hp_data_protector_installed.nasl");
  script_require_ports("Services/hp_dataprotector", 5555);
  script_mandatory_keys("hp_data_protector/installed");

  script_xref(name:"URL", value:"http://marc.info/?l=bugtraq&m=131188787531606&w=2");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103547/HPSBMU02669-SSRT100346-3.txt");
  script_xref(name:"URL", value:"http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02940981");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial of service
  condition.");
  script_tag(name:"affected", value:"HP (OpenView Storage) Data Protector Manager version 6.11 and prior.");
  script_tag(name:"insight", value:"The flaw is caused by an error in the Media Management Daemon (mmd), which
  could be exploited by remote attackers to crash an affected server.");
  script_tag(name:"summary", value:"This host is running HP (OpenView Storage) Data Protector Manager and is prone
  to denial of service vulnerability.");
  script_tag(name:"solution", value:"Apply the patch  *****
  NOTE : Ignore this warning, if above mentioned patch is already applied.
  *****");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://support.openview.hp.com/selfsolve/patches");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less_equal( version:vers, test_version:"06.11" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"06.12" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );