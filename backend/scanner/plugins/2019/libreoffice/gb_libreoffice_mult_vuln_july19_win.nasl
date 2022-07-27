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

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815422");
  script_version("2019-07-23T12:43:26+0000");
  script_cve_id("CVE-2019-9848", "CVE-2019-9849");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-07-23 12:43:26 +0000 (Tue, 23 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-19 17:12:56 +0530 (Fri, 19 Jul 2019)");
  script_name("LibreOffice Multiple Vulnerabilities July19 (Windows)");

  script_tag(name:"summary", value:"This host is installed with LibreOffice and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An improper validation for user supplied input when document event feature
    trigger LibreLogo to execute python contained within a document.

  - Remote bullet graphics were omitted from stealth mode protection.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary python commands silently without warning and retrieve
  remote resources from untrusted locations.");

  script_tag(name:"affected", value:"LibreOffice prior to 6.2.5 on Windows.");

  script_tag(name:"solution", value:"Upgrade to LibreOffice version 6.2.5 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2019-9848/");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2019-9849/");
  script_xref(name:"URL", value:"https://www.libreoffice.org/download/download/");
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_libreoffice_detect_portable_win.nasl");
  script_mandatory_keys("LibreOffice/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"6.2.5"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.2.5", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
