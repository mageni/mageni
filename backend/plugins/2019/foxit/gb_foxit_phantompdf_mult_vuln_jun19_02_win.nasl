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

CPE = "cpe:/a:foxitsoftware:phantompdf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815228");
  script_version("2019-07-04T09:58:18+0000");
  script_cve_id("CVE-2018-17687", "CVE-2018-17688", "CVE-2018-17689", "CVE-2018-17690",
                "CVE-2018-17691", "CVE-2018-17692", "CVE-2018-17693", "CVE-2018-17694",
                "CVE-2018-17695", "CVE-2018-17698", "CVE-2018-17700", "CVE-2018-17701",
                "CVE-2018-17706");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-07-04 09:58:18 +0000 (Thu, 04 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-06-28 15:20:18 +0530 (Fri, 28 Jun 2019)");
  script_name("Foxit PhantomPDF Multiple Vulnerabilities-June 2019 (Windows)-02");

  script_tag(name:"summary", value:"The host is installed with Foxit PhantomPDF and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An issue in handling of the setItems method of a ComboBox resulting in lack of
    validating the existence of an object prior to performing operations on the object.

  - An issue in handling of the fillColor property of a radio button resulting from
    lack of validating the existence of an object prior to performing operations on the
    object.

  - An issue in handling of Array.prototype.concat resulting from lack of proper
    validation of user-supplied data, which can result in a read past the end of
    an allocated object.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers
  to execute arbitrary code.");

  script_tag(name:"affected", value:"Foxit PhantomPDF versions before 8.3.7.38094 and 9.x to 9.2.0.9297 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Foxit PhantomPDF 8.3.8 or 9.3 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.foxitsoftware.com");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_phantom_reader_detect.nasl");
  script_mandatory_keys("foxit/phantompdf/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
pdfVer = infos['version'];
pdfPath = infos['location'];

if(version_is_less_equal(version:pdfVer, test_version:"8.3.7.38093")){
  vulnerable_range = "prior to 8.3.8";
}

else if(version_in_range(version:pdfVer, test_version:"9.0", test_version2:"9.2.0.9297")){
  vulnerable_range = "prior to 9.3";
}

if(vulnerable_range)
{
  report = report_fixed_ver(installed_version:pdfVer, fixed_version:vulnerable_range, install_path:pdfPath);
  security_message(data:report);
  exit(0);
}
exit(99);
