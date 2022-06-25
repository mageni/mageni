##############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Acrobat DC (Continuous Track) Security Updates(apsb18-41)-Mac OS X
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
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

CPE = "cpe:/a:adobe:acrobat_dc_continuous";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814383");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-15998", "CVE-2018-15987", "CVE-2018-16004", "CVE-2018-19720",
                "CVE-2018-16045", "CVE-2018-16044", "CVE-2018-16018", "CVE-2018-19715",
                "CVE-2018-19713", "CVE-2018-19708", "CVE-2018-19707", "CVE-2018-19700",
                "CVE-2018-19698", "CVE-2018-16046", "CVE-2018-16040", "CVE-2018-16039",
                "CVE-2018-16037", "CVE-2018-16036", "CVE-2018-16029", "CVE-2018-16027",
                "CVE-2018-16026", "CVE-2018-16025", "CVE-2018-16014", "CVE-2018-16008",
                "CVE-2018-16003", "CVE-2018-15994", "CVE-2018-15993", "CVE-2018-15992",
                "CVE-2018-15991", "CVE-2018-15990", "CVE-2018-19702", "CVE-2018-16016",
                "CVE-2018-16000", "CVE-2018-15999", "CVE-2018-15988", "CVE-2018-19716",
                "CVE-2018-16021", "CVE-2018-12830", "CVE-2018-19717", "CVE-2018-19714",
                "CVE-2018-19712", "CVE-2018-19711", "CVE-2018-19710", "CVE-2018-19709",
                "CVE-2018-19706", "CVE-2018-19705", "CVE-2018-19704", "CVE-2018-19703",
                "CVE-2018-19701", "CVE-2018-19699", "CVE-2018-16047", "CVE-2018-16043",
                "CVE-2018-16041", "CVE-2018-16038", "CVE-2018-16035", "CVE-2018-16034",
                "CVE-2018-16033", "CVE-2018-16032", "CVE-2018-16031", "CVE-2018-16030",
                "CVE-2018-16028", "CVE-2018-16024", "CVE-2018-16023", "CVE-2018-16022",
                "CVE-2018-16020", "CVE-2018-16019", "CVE-2018-16017", "CVE-2018-16015",
                "CVE-2018-16013", "CVE-2018-16012", "CVE-2018-16010", "CVE-2018-16006",
                "CVE-2018-16005", "CVE-2018-16002", "CVE-2018-16001", "CVE-2018-15997",
                "CVE-2018-15996", "CVE-2018-15989", "CVE-2018-15985", "CVE-2018-15984",
                "CVE-2018-19719", "CVE-2018-16009", "CVE-2018-16007", "CVE-2018-15995",
                "CVE-2018-15986", "CVE-2018-16042", "CVE-2018-19728");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-12-13 12:27:21 +0530 (Thu, 13 Dec 2018)");

  script_name("Adobe Acrobat DC (Continuous Track) Security Updates(apsb18-41)-Mac OS X");

  script_tag(name:"summary", value:"This host is installed with Adobe Acrobat DC
  (Continuous Track) and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple buffer errors.

  - Multiple untrusted pointer dereference errors.

  - Multiple security bypass errors.

  - Multiple use after free errors.

  - Multiple out-of-bounds write and read errors.

  - Multiple heap overflow errors.

  - Multiple integer overflow errors");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to execute arbitrary code, escalate privileges and
  disclose sensitive information.");

  script_tag(name:"affected", value:"Adobe Acrobat DC (Continuous Track) versions
  2019.008.20080 and earlier on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat DC Continuous
  version 2019.010.20064 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb18-41.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_dc_cont_detect_macosx.nasl");
  script_mandatory_keys("Adobe/AcrobatDC/Continuous/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"19.010.20064"))
{
  report =  report_fixed_ver(installed_version:vers, fixed_version:"2019.010.20064", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
