###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_tsm_fastback_mult_vuln_jul15.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# IBM Tivoli Storage Manager FastBack Multiple Vulnerabilities - Jul15
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:ibm:tivoli_storage_manager_fastback";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805900");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-1986", "CVE-2015-1965", "CVE-2015-1964", "CVE-2015-1963",
                "CVE-2015-1962", "CVE-2015-1954", "CVE-2015-1953", "CVE-2015-1949",
                "CVE-2015-1948", "CVE-2015-1942", "CVE-2015-1941", "CVE-2015-1938",
                "CVE-2015-1930", "CVE-2015-1929", "CVE-2015-1925", "CVE-2015-1924",
                "CVE-2015-1923");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-07-03 14:41:58 +0530 (Fri, 03 Jul 2015)");
  script_name("IBM Tivoli Storage Manager FastBack Multiple Vulnerabilities - Jul15");

  script_tag(name:"summary", value:"This host is installed with IBM Tivoli Storage
  Manager FastBack and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws exists due to,

  - Multiple buffer overflow errors as user-supplied input is not properly
    validated.

  - Multiple unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to conduct a denial of service attack or potentially allowing the
  execution of arbitrary code.");

  script_tag(name:"affected", value:"IBM Tivoli Storage Manager FastBack version
  6.1.x through 6.1.11.1");

  script_tag(name:"solution", value:"Upgrade to IBM Tivoli Storage Manager FastBack
  version 6.1.12 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21959398");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_ibm_tsm_fastback_detect.nasl");
  script_mandatory_keys("IBM/Tivoli/Storage/Manager/FastBack/Win/Ver");
  script_xref(name:"URL", value:"https://www.ibm.com");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!tivVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:tivVer, test_version:"6.1.0", test_version2:"6.1.11.1"))
{
  report = 'Installed version: ' + tivVer + '\n' +
           'Fixed version:     ' + '6.1.12' + '\n';
  security_message(data:report);
  exit(0);
}
