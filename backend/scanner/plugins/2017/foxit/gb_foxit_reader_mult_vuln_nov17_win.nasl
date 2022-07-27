###############################################################################
# OpenVAS Vulnerability Test
#
# Foxit Reader Multiple Vulnerabilities Nov17 (Windows)
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

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812100");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2017-10941", "CVE-2017-10942", "CVE-2017-10943",
                "CVE-2017-10944", "CVE-2017-10945", "CVE-2017-10953");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2017-11-10 11:34:48 +0530 (Fri, 10 Nov 2017)");
  script_name("Foxit Reader Multiple Vulnerabilities Nov17 (Windows)");

  script_tag(name:"summary", value:"The host is installed with Foxit Reader
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaw exists due to,

  - The lack of proper validation of a user-supplied string before using it to
    execute a system call.

  - The lack of validating the existence of an object prior to performing operations
    on the object.

  - The lack of proper validation of user-supplied data, which can result in a read
    past the end of an allocated object.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code, or cause denial of service condition or
  disclose sensitive information.");

  script_tag(name:"affected", value:"Foxit Reader version 8.3.0.14878 and prior.");

  script_tag(name:"solution", value:"Upgrade to Foxit Reader version 8.3.1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.us-cert.gov/ncas/bulletins/SB17-310");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  script_xref(name:"URL", value:"http://www.foxitsoftware.com");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
foxitVer = infos['version'];
foxPath = infos['location'];

if(version_is_less_equal(version:foxitVer, test_version:"8.3.0.14878"))
{
  report = report_fixed_ver(installed_version:foxitVer, fixed_version:"8.3.1", install_path:foxPath);
  security_message(data:report);
  exit(0);
}
exit(0);
