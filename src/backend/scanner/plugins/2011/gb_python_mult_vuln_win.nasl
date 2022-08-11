##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_python_mult_vuln_win.nasl 12358 2018-11-15 07:57:20Z cfischer $
#
# Python Multiple Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801797");
  script_version("$Revision: 12358 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-15 08:57:20 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2011-06-07 13:29:28 +0200 (Tue, 07 Jun 2011)");
  script_cve_id("CVE-2011-1521");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_name("Python Multiple Vulnerabilities (Windows)");
  script_dependencies("gb_python_detect_win.nasl");
  script_mandatory_keys("python6432/win/detected");

  script_xref(name:"URL", value:"http://bugs.python.org/issue11662");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=690560");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2011/03/24/5");
  script_xref(name:"URL", value:"http://hg.python.org/cpython/file/5937d2119a20/Lib/test/test_urllib2.py");

  script_tag(name:"insight", value:"The flaws are due to error in handling 'ftp://' and 'file://' URL
  schemes in the Python urllib and urllib2 extensible libraries processed the urllib open URL request.");

  script_tag(name:"summary", value:"This host is installed with Python and is prone to multiple
  vulnerabilities.");

  script_tag(name:"solution", value:"Update to version 2.7.2/3.2.1 or later.");

  script_tag(name:"impact", value:"Successful exploitation could allows attackers to access sensitive information
  or cause a denial of service of a Python web application, processing URLs, via
  a specially-crafted urllib open URL request.");

  script_tag(name:"affected", value:"Python version 2.x before 2.7.2 and 3.x before 3.2.1");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
pyVer = infos['version'];
pypath = infos['location'];

if(version_in_range(version:pyVer, test_version:"2.0", test_version2:"2.7.1") ||
   version_in_range(version:pyVer, test_version:"3.0", test_version2:"3.2.0")){
  report = report_fixed_ver(installed_version:pyVer, fixed_version:"2.7.2/3.2.1", install_path:pypath);
  security_message(data:report);
}

exit(0);