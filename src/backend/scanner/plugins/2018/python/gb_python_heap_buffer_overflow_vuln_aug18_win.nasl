###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_python_heap_buffer_overflow_vuln_aug18_win.nasl 12358 2018-11-15 07:57:20Z cfischer $
#
# Python Heap Buffer Overflow Vulnerability Aug18 (Windows)
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813919");
  script_version("$Revision: 12358 $");
  script_cve_id("CVE-2018-1000030");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-15 08:57:20 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-08-22 11:28:01 +0530 (Wed, 22 Aug 2018)");
  script_name("Python Heap Buffer Overflow Vulnerability Aug18 (Windows)");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_python_detect_win.nasl");
  script_mandatory_keys("python6432/win/detected");

  script_xref(name:"URL", value:"https://bugs.python.org/issue31530");
  script_xref(name:"URL", value:"https://www.python.org");

  script_tag(name:"summary", value:"This host is installed with python and is
  prone to heap buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exist due to an improper notification
  mechanism on buffer reallocation and corruption in file's internal readahead
  buffer which while processing large amounts of data with multiple threads could
  create a condition where a buffer that gets allocated with one thread is
  reallocated due to a large size of input.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause heap buffer overflow.");

  script_tag(name:"affected", value:"Python 2.7.x before version 2.7.15 on Windows");

  script_tag(name:"solution", value:"Upgrade to Python 2.7.15 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
pVer = infos['version'];
pPath = infos['location'];

##2.7.15 == 2.7.15150
if(version_in_range(version: pVer, test_version: "2.7.0", test_version2: "2.7.15149")){
  report = report_fixed_ver(installed_version:pVer, fixed_version:"2.7.15", install_path:pPath);
  security_message(data:report);
}

exit(0);