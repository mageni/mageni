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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:adobe:acrobat_reader_dc_continuous";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814847");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-19725", "CVE-2019-7018", "CVE-2019-7019", "CVE-2019-7020",
                "CVE-2019-7021", "CVE-2019-7022", "CVE-2019-7023", "CVE-2019-7024",
                "CVE-2019-7025", "CVE-2019-7026", "CVE-2019-7027", "CVE-2019-7028",
                "CVE-2019-7029", "CVE-2019-7030", "CVE-2019-7031", "CVE-2019-7032",
                "CVE-2019-7033", "CVE-2019-7034", "CVE-2019-7035", "CVE-2019-7036",
                "CVE-2019-7037", "CVE-2019-7038", "CVE-2019-7039", "CVE-2019-7040",
                "CVE-2019-7041", "CVE-2019-7042", "CVE-2019-7043", "CVE-2019-7044",
                "CVE-2019-7045", "CVE-2019-7046", "CVE-2019-7047", "CVE-2019-7048",
                "CVE-2019-7049", "CVE-2019-7050", "CVE-2019-7051", "CVE-2019-7052",
                "CVE-2019-7053", "CVE-2019-7054", "CVE-2019-7055", "CVE-2019-7056",
                "CVE-2019-7057", "CVE-2019-7058", "CVE-2019-7059", "CVE-2019-7060",
                "CVE-2019-7062", "CVE-2019-7063", "CVE-2019-7064", "CVE-2019-7065",
                "CVE-2019-7066", "CVE-2019-7067", "CVE-2019-7068", "CVE-2019-7069",
                "CVE-2019-7070", "CVE-2019-7071", "CVE-2019-7072", "CVE-2019-7073",
                "CVE-2019-7074", "CVE-2019-7075", "CVE-2019-7076", "CVE-2019-7077",
                "CVE-2019-7078", "CVE-2019-7079", "CVE-2019-7080", "CVE-2019-7081",
                "CVE-2019-7082", "CVE-2019-7083", "CVE-2019-7084", "CVE-2019-7085",
                "CVE-2019-7086", "CVE-2019-7087", "CVE-2019-7089");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2019-02-14 11:05:10 +0530 (Thu, 14 Feb 2019)");
  script_name("Adobe Acrobat Reader DC (Continuous Track) Security Updates(apsb19-07)-Mac OS X");

  script_tag(name:"summary", value:"This host is installed with Adobe Acrobat
  Reader DC (Continuous Track) and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple buffer errors.

  - A data leakage error.

  - An integer overflow error.

  - Multiple out-of-bounds read errors.

  - Multiple security bypass errors.

  - Multiple out-of-bounds write errors.

  - Multiple type confusion errors.

  - Multiple untrusted pointer dereference errors.

  - Multiple use after free errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code in the context of the current user,
  escalate privileges and gain access to sensitive information.");

  script_tag(name:"affected", value:"Adobe Acrobat Reader DC (Continuous Track)
  2019.010.20069 and earlier versions on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat Reader DC Continuous
  version 2019.010.20091 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb19-07.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_reader_dc_cont_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Acrobat/ReaderDC/Continuous/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

# 2019.010.20091 == 19.010.20091
if(version_is_less(version:vers, test_version:"19.010.20091"))
{
  report =  report_fixed_ver(installed_version:vers, fixed_version:"19.010.20091", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
