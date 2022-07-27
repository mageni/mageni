###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_goldengate_mult_unspecified_vuln.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# Oracle GoldenGate Multiple Unspecified Vulnerabilities Feb16 (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
##############################################################################

CPE = "cpe:/a:oracle:goldengate";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807249");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2016-0452", "CVE-2016-0451", "CVE-2016-0450");
  script_bugtraq_id(81122, 81125, 81117);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-02-12 13:49:29 +0530 (Fri, 12 Feb 2016)");
  script_name("Oracle GoldenGate Multiple Unspecified Vulnerabilities Feb16 (Windows)");

  script_tag(name:"summary", value:"The host is installed with Oracle GoldenGate
  and is prone to multiple unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaw exists due to unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to have an impact on confidentiality, integrity and availability
  via unknown vectors.");

  script_tag(name:"affected", value:"Oracle GoldenGate 11.2 and 12.1.2 on Windows.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_oracle_goldengate_detect.nasl");
  script_mandatory_keys("Oracle/GoldenGate/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!golVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:golVer, test_version:"11.2")||
   version_is_equal(version:golVer, test_version:"12.1.2"))
{
  report = report_fixed_ver(installed_version:golVer, fixed_version:"Apply the patch");
  security_message(data:report);
  exit(0);
}
