###############################################################################
# OpenVAS Vulnerability Test
#
# Python Elementtree Denial of Service Vulnerability (Windows)
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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

CPE = 'cpe:/a:python:python';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814304");
  script_version("2019-04-26T13:30:35+0000");
  script_cve_id("CVE-2018-14647");
  script_bugtraq_id(105396);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-04-26 13:30:35 +0000 (Fri, 26 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-10-03 17:02:15 +0530 (Wed, 03 Oct 2018)");

  script_name("Python Elementtree Denial of Service Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_python_detect_win.nasl");
  script_mandatory_keys("python6432/win/detected");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/elementree_salt.html");
  script_xref(name:"URL", value:"https://bugs.python.org/issue34623");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-14647");

  script_tag(name:"summary", value:"This host is running Python and is prone
  to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because Python's elementtree
  C accelerator fails to initialise Expat's hash salt during initialization");

  script_tag(name:"impact", value:"Successful exploitation allows denial of
  service attacks against Expat by constructing an XML document that would cause
  pathological hash collisions in Expat's internal data structures, consuming large amounts CPU and RAM.");

  script_tag(name:"affected", value:"Python versions 3.8, 3.7, 3.6, 3.5, 3.4 and 2.7 on Windows");

  script_tag(name:"solution", value:"Update to version 2.7.16, 3.6.7, 3.7.1 or later");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

pyVer = infos['version'];
pypath = infos['location'];

if (version_is_less(version: pyVer, test_version: "2.7.16")) {
  report = report_fixed_ver(installed_version: pyVer, fixed_version: "2.7.16", install_path: pypath);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: pyVer, test_version: "3.4", test_version: "3.6.6")) {
  report = report_fixed_ver(installed_version: pyVer, fixed_version: "3.6.7", install_path: pypath);
  security_message(port: 0, data:report);
  exit(0);
}

if (version_is_equal(version: pyVer, test_version: "3.7.0")) {
  report = report_fixed_ver(installed_version: pyVer, fixed_version: "3.7.1", install_path: pypath);
  security_message(port: 0, data:report);
  exit(0);
}

exit(0);
