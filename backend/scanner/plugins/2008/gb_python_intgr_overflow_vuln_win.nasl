###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_python_intgr_overflow_vuln_win.nasl 12492 2018-11-22 14:07:01Z cfischer $
#
# Python Multiple Integer Overflow Vulnerabilities (Windows)
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

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800056");
  script_version("$Revision: 12492 $");
  script_cve_id("CVE-2008-5031");
  script_tag(name:"last_modification", value:"$Date: 2018-11-22 15:07:01 +0100 (Thu, 22 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-11-14 10:43:16 +0100 (Fri, 14 Nov 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Python Multiple Integer Overflow Vulnerabilities (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_python_detect_win.nasl");
  script_mandatory_keys("python6432/win/detected");

  script_xref(name:"URL", value:"http://www.python.org/");

  script_tag(name:"impact", value:"Remote exploitation will allow execution of arbitrary code via large number
  of integer values to modules.");

  script_tag(name:"affected", value:"Python 2.5.2 on Windows.");

  script_tag(name:"insight", value:"The flaw exists due the the way it handles large integer values in the
  tabsize arguments as input to expandtabs methods (string_expandtabs and
  nicode_expandtabs) in stringobject.c and unicodeobject.c.");

  script_tag(name:"solution", value:"Upgrade to Python 2.5.5 or later.");

  script_tag(name:"summary", value:"This host has Python installed and is prone to integer overflow
  vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos['version'];
path = infos['location'];

if( version_is_less_equal( version:vers, test_version:"2.5.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.5.5", install_path:path );
  security_message( port:0, data:report );
}

exit( 0 );