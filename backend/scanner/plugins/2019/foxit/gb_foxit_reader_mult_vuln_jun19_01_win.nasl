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

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815226");
  script_version("2019-07-04T09:58:18+0000");
  script_cve_id("CVE-2019-6754", "CVE-2019-6755", "CVE-2019-6759", "CVE-2019-6753",
                "CVE-2019-6757", "CVE-2019-6758", "CVE-2019-6758", "CVE-2019-6760",
                "CVE-2019-6761", "CVE-2019-6763", "CVE-2019-6764", "CVE-2019-6766",
                "CVE-2019-6767", "CVE-2019-6768", "CVE-2019-6769", "CVE-2019-6770",
                "CVE-2019-6771", "CVE-2019-6772", "CVE-2019-6773", "CVE-2019-6753",
                "CVE-2019-6756", "CVE-2019-6757");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-07-04 09:58:18 +0000 (Thu, 04 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-06-28 11:15:36 +0530 (Fri, 28 Jun 2019)");
  script_name("Foxit Reader Multiple Vulnerabilities June 2019 (Windows)-01");

  script_tag(name:"summary", value:"The host is installed with Foxit Reader and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An issue in localFileStorage method resulting from lack of proper validation
    of a user-supplied path prior to using it in file operations.

  - An issue in ConvertToPDF_x86.dll resulting from the lack of proper validation of
    user-supplied data, which can result in a write past the end of an
    allocated object.

  - An issue in handling of the Stuff method resulting from the lack of proper
    validation of user-supplied data, which can result in an integer
    overflow before writing to memory.

  - An issue in ConvertToPDF_x86.dll resulting from the lack of validating the
    existence of an object prior to performing operations on the object.

  - An issue in XFA CXFA_FFDocView object resulting from the lack of validating
    the existence of an object prior to performing operations on the object.

  - An issue in ToggleFormsDesign method of the Foxit.FoxitReader.Ctl ActiveX object
    resulting from lack of validating the existence of an object prior to performing
    operations on the object.

  - Improper validation of user-supplied data, which can result in a write past the
    end of an allocated structure.

  - An issue in removeField method when processing AcroForms resulting from lack of
    validating the existence of an object prior to performing operations on the object.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers
  to execute arbitrary code and disclose sensitive information.");

  script_tag(name:"affected", value:"Foxit Reader version 9.4.1.16828 and earlier
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Foxit Reader 9.5 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.foxitsoftware.com");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
pdfVer = infos['version'];
pdfPath = infos['location'];

if(version_is_less_equal(version:pdfVer, test_version:"9.4.1.16828"))
{
  report = report_fixed_ver(installed_version:pdfVer, fixed_version:"9.5", install_path:pdfPath);
  security_message(data:report);
  exit(0);
}
exit(99);
