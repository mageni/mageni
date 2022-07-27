###############################################################################
# OpenVAS Vulnerability Test
#
# Python Heap Buffer Overflow Vulnerability Aug18 (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.813920");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-1000030");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-08-22 13:24:04 +0530 (Wed, 22 Aug 2018)");
  script_name("Python Heap Buffer Overflow Vulnerability Aug18 (Mac OS X)");

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

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"affected", value:"Python 2.7.x before version 2.7.15 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Python 2.7.15 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugs.python.org/issue31530");
  script_xref(name:"URL", value:"https://www.python.org");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_python_detect_macosx.nasl");
  script_mandatory_keys("python/MacOSX/Version");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
pVer = infos['version'];
pPath = infos['location'];

if(version_in_range(version: pVer, test_version: "2.7.0", test_version2: "2.7.14"))
{
  report = report_fixed_ver(installed_version:pVer, fixed_version:"2.7.15", install_path:pPath);
  security_message(data:report);
  exit(0);
}
