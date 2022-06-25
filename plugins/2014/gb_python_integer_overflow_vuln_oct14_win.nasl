###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_python_integer_overflow_vuln_oct14_win.nasl 12358 2018-11-15 07:57:20Z cfischer $
#
# Python Integer Overflow Vulnerability - 01 Oct14 (Windows)
#
# Authors:
# Deepmala <kdeepmala@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804939");
  script_version("$Revision: 12358 $");
  script_cve_id("CVE-2014-7185");
  script_bugtraq_id(70089);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-15 08:57:20 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-10-17 12:50:02 +0530 (Fri, 17 Oct 2014)");
  script_name("Python Integer Overflow Vulnerability - 01 Oct14 (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_python_detect_win.nasl");
  script_mandatory_keys("python6432/win/detected");

  script_xref(name:"URL", value:"https://www.python.org");
  script_xref(name:"URL", value:"http://bugs.python.org/issue2183");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/96193");

  script_tag(name:"summary", value:"The host is installed with Python
  and is prone to integer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists as the user-supplied input is
  not properly validated when handling large buffer sizes and/or offsets.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information or cause a denial
  of service.");

  script_tag(name:"affected", value:"Python 2.7.x before version 2.7.8 on
  Windows.");

  script_tag(name:"solution", value:"Upgrade to version 2.7.8 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
pyVer = infos['version'];
pypath = infos['location'];

if(version_in_range(version:pyVer, test_version:"2.7", test_version2:"2.7.7150")){
  report = report_fixed_ver(installed_version:pyVer, fixed_version:"2.7.8", install_path:pypath);
  security_message(data:report);
}

exit(0);