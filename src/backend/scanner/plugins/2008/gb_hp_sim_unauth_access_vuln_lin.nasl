###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_sim_unauth_access_vuln_lin.nasl 14240 2019-03-17 15:50:45Z cfischer $
#
# HP Systems Insight Manager Unauthorized Access Vulnerability (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800034");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-10-21 16:25:40 +0200 (Tue, 21 Oct 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2008-4412");
  script_bugtraq_id(31777);
  script_name("HP Systems Insight Manager Unauthorized Access Vulnerability (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32287/");
  script_xref(name:"URL", value:"http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01571962");
  script_xref(name:"URL", value:"http://h20392.www2.hp.com/portal/swdepot/index.do");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to gain unauthorized
  access to the data.");

  script_tag(name:"affected", value:"HP SIM prior to 5.2 with Update 2 (C.05.02.02.00) on Linux");

  script_tag(name:"insight", value:"The flaw is due to an error in the application which allows unauthorized
  access to certain data.");

  script_tag(name:"solution", value:"Update to HP SIM version 5.2 with Update 2 (C.05.02.02.00)");

  script_tag(name:"summary", value:"This host is running HP Systems Insight Manager (SIM) and is prone
  to security bypass vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

simName = find_file( file_name:"mxversion", file_path:"/", useregex:TRUE, regexpar:"$", sock:sock );
foreach binaryName( simName ) {

  binaryName = chomp( binaryName );
  if( ! binaryName ) continue;

  simVer = get_bin_version( full_prog_name:binaryName, sock:sock, ver_pattern:"Linux ([^ ]+)" );
  if( simVer ) {
    if( version_is_less( version:simVer[1], test_version:"C.05.02.02.00" ) ) {
      report = report_fixed_ver( installed_version:simVer[1], fixed_version:"C.05.02.02.00", install_path:binaryName );
      security_message( port:0, data:report );
      ssh_close_connection();
      exit( 0 );
    }
  }
}

ssh_close_connection();
exit( 99 );