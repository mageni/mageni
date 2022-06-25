###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_tsm_fastback_mult_buf_overflow_vuln_aug16.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# IBM Tivoli Storage Manager FastBack Server Multiple Buffer Overflow Vulnerabilities Aug16
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.

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
  script_oid("1.3.6.1.4.1.25623.1.0.808635");
  script_version("$Revision: 14181 $");
  script_cve_id("CVE-2016-0212", "CVE-2016-0213", "CVE-2016-0216");
  script_bugtraq_id(83280, 83281, 83278);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-08-04 13:00:07 +0530 (Thu, 04 Aug 2016)");
  script_name("IBM Tivoli Storage Manager FastBack Server Multiple Buffer Overflow Vulnerabilities Aug16");

  script_tag(name:"summary", value:"This host is installed with IBM Tivoli Storage
  Manager FastBack and is prone to multiple buffer overflow vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to an improper bounds
  checking in server command processing.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to overflow a buffer and execute arbitrary code on the system with
  system privileges or cause the application to crash.");

  script_tag(name:"affected", value:"IBM Tivoli Storage Manager FastBack server
  version 5.5 and 6.1 through 6.1.11.1");

  script_tag(name:"solution", value:"Upgrade to IBM Tivoli Storage Manager FastBack
  server version 6.1.12 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21975358");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("gb_ibm_tsm_fastback_detect.nasl");
  script_mandatory_keys("IBM/Tivoli/Storage/Manager/FastBack/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!tivVer = get_app_version(cpe:CPE)){
  exit(0);
}

##For FastBack 5.5, IBM recommends upgrading to a fixed, supported version of FastBack (6.1.12).
if(version_is_equal(version:tivVer, test_version:"5.5") ||
   version_in_range(version:tivVer, test_version:"6.1.0", test_version2:"6.1.11.1"))
{
  report = report_fixed_ver(installed_version:tivVer, fixed_version:"6.1.12");
  security_message(data:report);
  exit(0);
}
