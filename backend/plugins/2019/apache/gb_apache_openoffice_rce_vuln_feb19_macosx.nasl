# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:openoffice:openoffice.org";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814828");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-16858");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2019-02-07 11:49:32 +0530 (Thu, 07 Feb 2019)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Apache OpenOffice Remote Code Execution Vulnerability Feb19 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Apache OpenOffice
  Writer and is prone to remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists in the file 'pydoc.py' in
  LibreOffices Python interpreter which accepts and executes arbitrary commands.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code and traverse directories.");

  script_tag(name:"affected", value:"Apache OpenOffice Writer version 4.1.6 on
  Mac OS X");

  script_tag(name:"solution", value:"No known solution is available as of 03rd April, 2019.
  Information regarding this issue will be updated once solution details are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_xref(name:"URL", value:"https://thehackernews.com/2019/02/hacking-libreoffice-openoffice.html");
  script_xref(name:"URL", value:"https://www.openoffice.org/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openoffice_detect_macosx.nasl");
  script_mandatory_keys("OpenOffice/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

opver = infos['version'];
opath = infos['location'];

if(version_is_less_equal(version: opver, test_version:"4.1.6")) {
  report = report_fixed_ver(installed_version:opver, fixed_version:"NoneAvailable", install_path:opath);
  security_message(data:report);
  exit(0);
}

exit(99);
