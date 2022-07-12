###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_tsm_fastback_mult_bof_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# IBM Tivoli Storage Manager FastBack Multiple Buffer Overflow Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.805599");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-1896", "CVE-2015-0120");
  script_bugtraq_id(74024, 74021);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-07-03 09:35:08 +0530 (Fri, 03 Jul 2015)");
  script_name("IBM Tivoli Storage Manager FastBack Multiple Buffer Overflow Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with IBM Tivoli Storage
  Manager FastBack and is prone to multiple buffer overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An overflow condition in the mount service.

  - User-supplied input is not properly validated when passed to
  the CRYPTO_S_EncryptBufferToBuffer function.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to conduct a denial of service attack or potentially allowing the execution of
  arbitrary code.");

  script_tag(name:"affected", value:"IBM Tivoli Storage Manager FastBack version
  6.1.x before 6.1.11.1");

  script_tag(name:"solution", value:"Upgrade to IBM Tivoli Storage Manager FastBack
  version 6.1.11.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21700549");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21700536");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
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

if(version_in_range(version:tivVer, test_version:"6.1.0", test_version2:"6.1.11.0"))
{
  report = 'Installed version: ' + tivVer + '\n' +
           'Fixed version:     ' + '6.1.11.1' + '\n';
  security_message(data:report);
  exit(0);
}
