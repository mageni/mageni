###############################################################################
# OpenVAS Vulnerability Test
#
# XnView Multiple Vulnerabilities
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:xnview:xnview";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811402");
  script_version("2019-05-03T13:51:56+0000");
  script_cve_id("CVE-2017-9914", "CVE-2017-9912", "CVE-2017-9910", "CVE-2017-9911",
                "CVE-2017-9908", "CVE-2017-9909", "CVE-2017-9906", "CVE-2017-9907",
                "CVE-2017-9905", "CVE-2017-9903", "CVE-2017-9904", "CVE-2017-9901",
                "CVE-2017-9902", "CVE-2017-9900", "CVE-2017-9898", "CVE-2017-9899",
                "CVE-2017-9897", "CVE-2017-9896", "CVE-2017-9895", "CVE-2017-9894",
                "CVE-2017-9893", "CVE-2017-9529", "CVE-2017-8781", "CVE-2017-8381",
                "CVE-2017-8282", "CVE-2017-10782", "CVE-2017-10783", "CVE-2017-10781",
                "CVE-2017-10779", "CVE-2017-10780", "CVE-2017-10777", "CVE-2017-10778",
                "CVE-2017-10776", "CVE-2017-10774", "CVE-2017-10775", "CVE-2017-10772",
                "CVE-2017-10773", "CVE-2017-10770", "CVE-2017-10771", "CVE-2017-10769",
                "CVE-2017-10767", "CVE-2017-10768", "CVE-2017-10765", "CVE-2017-10766",
                "CVE-2017-10763", "CVE-2017-10764", "CVE-2017-10762", "CVE-2017-10760",
                "CVE-2017-10761", "CVE-2017-10758", "CVE-2017-10759", "CVE-2017-10757",
                "CVE-2017-10755", "CVE-2017-10756", "CVE-2017-10753", "CVE-2017-10754",
                "CVE-2017-10751", "CVE-2017-10752", "CVE-2017-10750", "CVE-2017-10748",
                "CVE-2017-10749", "CVE-2017-10747", "CVE-2017-10745", "CVE-2017-10746",
                "CVE-2017-10743", "CVE-2017-10744", "CVE-2017-10741", "CVE-2017-10742",
                "CVE-2017-10740", "CVE-2017-10738", "CVE-2017-10739", "CVE-2017-10736",
                "CVE-2017-10737", "CVE-2017-14284", "CVE-2017-14285", "CVE-2017-14282",
                "CVE-2017-14283", "CVE-2017-14280", "CVE-2017-14281", "CVE-2017-14278",
                "CVE-2017-14279", "CVE-2017-14277", "CVE-2017-14275", "CVE-2017-14276",
                "CVE-2017-14273", "CVE-2017-14274", "CVE-2017-14271", "CVE-2017-14272",
                "CVE-2017-14270", "CVE-2017-14541", "CVE-2017-14538", "CVE-2017-9913");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 13:51:56 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-08-07 19:41:51 +0530 (Mon, 07 Aug 2017)");
  script_name("XnView Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with XnView and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Read Access Violation on Block Data Move.

  - Data from Faulting Address controls Branch Selection.

  - Error Code (0xc000041d).

  - Data from Faulting Address is used as one or more arguments in a subsequent
    Function Call.

  - User Mode Write AV near NULL.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to to execute arbitrary code or cause a denial of service.");

  script_tag(name:"affected", value:"XnView Version 2.44 and earlier");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/wlinzi/security_advisories/tree/master/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_xnview_detect_win.nasl");
  script_mandatory_keys("XnView/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!xnVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less_equal(version:xnVer, test_version:"2.44")){
  report = report_fixed_ver(installed_version:xnVer, fixed_version:"NoneAvailable");
  security_message(data:report);
  exit(0);
}

exit(99);
