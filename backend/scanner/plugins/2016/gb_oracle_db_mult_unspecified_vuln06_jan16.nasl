###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_db_mult_unspecified_vuln06_jan16.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# Oracle Database Server Multiple Unspecified Vulnerabilities -06 Jan16
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
###############################################################################

CPE = "cpe:/a:oracle:database_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807042");
  script_version("$Revision: 14181 $");
  script_cve_id("CVE-2014-6577", "CVE-2015-4753", "CVE-2015-0455");
  script_bugtraq_id(72139, 75839, 74076);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-01-25 14:59:25 +0530 (Mon, 25 Jan 2016)");
  script_name("Oracle Database Server Multiple Unspecified Vulnerabilities -06 Jan16");

  script_tag(name:"summary", value:"This host is running  Oracle Database Server
  and is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An Unspecified vulnerability in the XML Developer's Kit for C component.

  - An Unspecified vulnerability in the RDBMS Support Tools component.

  - An Unspecified vulnerability in the XDB - XML Database component.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  authenticated and local attackers to affect confidentiality, integrity, and
  availability via unknown vectors.");

  script_tag(name:"affected", value:"Oracle Database Server versions
  11.2.0.3, 11.2.0.4, 12.1.0.1, and 12.1.0.2.");

  script_tag(name:"solution", value:"Apply the patche from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("oracle_tnslsnr_version.nasl");
  script_mandatory_keys("OracleDatabaseServer/installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!dbPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dbVer = get_app_version(cpe:CPE, port:dbPort)){
  exit(0);
}

if(dbVer =~ "^(12|11)")
{
  if(version_is_equal(version:dbVer, test_version:"12.1.0.1") ||
     version_is_equal(version:dbVer, test_version:"12.1.0.2") ||
     version_is_equal(version:dbVer, test_version:"11.2.0.3") ||
     version_is_equal(version:dbVer, test_version:"11.2.0.4"))
  {
    report = report_fixed_ver(installed_version:dbVer, fixed_version:"Apply the appropriate patch");
    security_message(data:report, port:dbPort);
    exit(0);
  }
}
