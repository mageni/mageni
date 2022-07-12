###############################################################################
# OpenVAS Vulnerability Test
#
# XnView Multiple DoS Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.811951");
  script_version("2019-05-03T13:51:56+0000");
  script_cve_id("CVE-2017-15787", "CVE-2017-15788", "CVE-2017-15786", "CVE-2017-15785",
		"CVE-2017-15784", "CVE-2017-15783", "CVE-2017-15782", "CVE-2017-15780",
		"CVE-2017-15781", "CVE-2017-15779", "CVE-2017-15778", "CVE-2017-15777",
		"CVE-2017-15776", "CVE-2017-15775", "CVE-2017-15774", "CVE-2017-15772",
		"CVE-2017-15773", "CVE-2017-15803", "CVE-2017-15802", "CVE-2017-15801",
                "CVE-2017-15789");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 13:51:56 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-10-25 12:35:33 +0530 (Wed, 25 Oct 2017)");

  script_name("XnView Multiple DoS Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with XnView and is
  prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Dll mishandling during an attempt to render the DLL icon.

  - Improper validation of '.dwg' files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to to execute arbitrary code or cause a denial of service.");

  script_tag(name:"affected", value:"XnView Version 2.43");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/wlinzi/security_advisories");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_xnview_detect_win.nasl");
  script_mandatory_keys("XnView/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!xnVer = get_app_version(cpe:CPE))
  exit(0);

if(version_is_equal(version:xnVer, test_version:"2.43")) {
  report = report_fixed_ver(installed_version:xnVer, fixed_version:"WillNotFix");
  security_message(data:report);
  exit(0);
}

exit(0);
