# OpenVAS Vulnerability Test
# $Id: gb_python_hash_collision_dos_vuln_win.nasl 12358 2018-11-15 07:57:20Z cfischer $
#
# Python 'Hash Collision' Denial of Service Vulnerability (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804632");
  script_version("$Revision: 12358 $");
  script_cve_id("CVE-2013-7040");
  script_bugtraq_id(64194);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-15 08:57:20 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-06-09 14:43:46 +0530 (Mon, 09 Jun 2014)");
  script_name("Python 'Hash Collision' Denial of Service Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_python_detect_win.nasl");
  script_mandatory_keys("python6432/win/detected");

  script_xref(name:"URL", value:"http://www.python.org/download");
  script_xref(name:"URL", value:"http://secunia.com/advisories/55955");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q4/439");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2013/12/09/3");

  script_tag(name:"summary", value:"This host is installed with Python and is prone to denial of service
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to an error within a hash generation function when hashing form
  posts and updating a hash table.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to cause a hash collision
  resulting in a denial of service.");

  script_tag(name:"affected", value:"Python version 2.7 before 3.4.");

  script_tag(name:"solution", value:"Upgrade to Python version 3.4 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
pyVer = infos['version'];
pypath = infos['location'];

if(version_in_range(version:pyVer, test_version:"2.7", test_version2:"3.3.5150")){
  report = report_fixed_ver(installed_version:pyVer, fixed_version:"3.4", install_path:pypath);
  security_message(data:report);
}

exit(0);