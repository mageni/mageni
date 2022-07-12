###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_sys_web_serv_bof_vuln_lin.nasl 12734 2018-12-10 09:21:32Z cfischer $
#
# Sun Java System Web Server Buffer Overflow Vulnerability (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

CPE = "cpe:/a:sun:java_system_web_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801147");
  script_version("$Revision: 12734 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-10 10:21:32 +0100 (Mon, 10 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-11-12 15:21:24 +0100 (Thu, 12 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Sun Java System Web Server Buffer Overflow Vulnerability (Linux)");
  script_cve_id("CVE-2009-3878");
  script_bugtraq_id(36813);
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_sun_one_java_sys_web_serv_detect_lin.nasl");
  script_mandatory_keys("Sun/JavaSysWebServ/Lin/Ver");

  script_xref(name:"URL", value:"http://intevydis.com/vd-list.shtml");
  script_xref(name:"URL", value:"http://www.intevydis.com/blog/?p=79");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37115");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3024");

  script_tag(name:"impact", value:"Successful exploitation lets the attackers to execute arbitrary
  code in the context of an affected system.");

  script_tag(name:"affected", value:"Sun Java System Web Server version 7.0 update 6 and prior on
  Linux.");

  script_tag(name:"insight", value:"An unspecified error that can be exploited to cause a buffer
  overflow.");

  script_tag(name:"solution", value:"Upgrade to version 7.0 update 7 or later.");

  script_tag(name:"summary", value:"This host has Sun Java Web Server running which is prone to
  Buffer Overflow vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos['version'];
path = infos['location'];

if( version_is_less_equal( version:vers, test_version:"7.0.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"7.0.7", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
