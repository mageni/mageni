###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_sys_web_serv_heap_bof_vuln_lin.nasl 12718 2018-12-08 12:55:00Z cfischer $
#
# Sun Java System Web Server Multiple Heap-based Buffer Overflow Vulnerabilities (Linux)
#
# Authors:
# Veerendra G <veerendragg@secpod.com>
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

CPE = "cpe:/a:sun:java_system_web_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800160");
  script_version("$Revision: 12718 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-08 13:55:00 +0100 (Sat, 08 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-02-02 07:26:26 +0100 (Tue, 02 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0387");
  script_bugtraq_id(37896);
  script_name("Sun Java System Web Server Multiple Heap-based Buffer Overflow Vulnerabilities (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_sun_one_java_sys_web_serv_detect_lin.nasl");
  script_mandatory_keys("Sun/JavaSysWebServ/Lin/Ver");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/55792");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Jan/1023488.html");
  script_xref(name:"URL", value:"http://intevydis.blogspot.com/2010/01/sun-java-system-web-server-70u7-digest.html");

  script_tag(name:"impact", value:"Successful exploitation lets the attackers to cause the application to crash
  or execute arbitrary code on the system by sending an overly long request in
  an 'Authorization: Digest' header.");

  script_tag(name:"affected", value:"Sun Java System Web Server version 7.0 update 7 on Linux.");

  script_tag(name:"insight", value:"An error exists in in webservd and admin server that can be exploited to
  overflow a buffer and execute arbitrary code on the system or cause the
  server to crash via a long string in an 'Authorization: Digest' HTTP
  header.");

  script_tag(name:"solution", value:"Upgrade to Sun Java System Web Server version 7.0 update 8 or later.");

  script_tag(name:"summary", value:"This host has Sun Java Web Server running which is prone to
  multiple Heap-based Buffer Overflow Vulnerabilities.");

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

if( version_is_equal( version:vers, test_version:"7.0.7" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"7.0.8", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );