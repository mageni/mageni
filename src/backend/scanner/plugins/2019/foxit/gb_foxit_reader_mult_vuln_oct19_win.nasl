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
  script_oid("1.3.6.1.4.1.25623.1.0.815477");
  script_version("2019-10-11T07:39:42+0000");
  script_cve_id("CVE-2019-5031", "CVE-2019-13123", "CVE-2019-13124", "CVE-2019-13326",
                "CVE-2019-13327", "CVE-2019-13328", "CVE-2019-13329", "CVE-2019-13330",
                "CVE-2019-13331", "CVE-2019-13332");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-10-11 07:39:42 +0000 (Fri, 11 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-04 19:05:15 +0530 (Fri, 04 Oct 2019)");
  script_name("Foxit Reader Multiple Vulnerabilities October 2019");

  script_tag(name:"summary", value:"The host is installed with Foxit Reader and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An unexpected error or out-of-memory in V8 Engine when executing certain
    JavaScript.

  - An error within the processing of fields within Acroform objects. The issue
    results from the lack of validating the existence of an object prior to
    performing operations on the object.

  - An error exists within the processing of TIF files. The issue results from
    the lack of proper validation of user-supplied data, which can result in a
    type confusion condition.

  - An error exists within the processing of JPG files. The issue results from
    the lack of proper validation of user-supplied data, which can result in a
    type confusion condition.

  - An error exists within the parsing of JPG files. The issue results from the
    lack of proper validation of user-supplied data, which can result in a read
    past the end of an allocated buffer.

  - An error exists within the processing of templates in XFA forms. The issue
    results from the lack of validating the existence of an object prior to
    performing operations on the object.

  - An error when parsing certain file data due to the access of null pointer
    without proper validation.

  - The nested calling of functions when parsing XML files.

  - The dereference of null pointer.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers
  to execute arbitrary code, bypass access controls and cause denial of service
  condition.");

  script_tag(name:"affected", value:"Foxit Reader version 9.6.0.25114 and earlier
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Foxit Reader 9.7 or later. Please
  see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/pdf-reader");
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

if(version_is_less_equal(version:pdfVer, test_version:"9.6.0.25114"))
{
  report = report_fixed_ver(installed_version:pdfVer, fixed_version:"9.7", install_path:pdfPath);
  security_message(data:report);
  exit(0);
}
exit(99);
