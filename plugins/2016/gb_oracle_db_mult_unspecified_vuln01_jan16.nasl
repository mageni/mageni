###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_db_mult_unspecified_vuln01_jan16.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# Oracle Database Server Multiple Unspecified Vulnerabilities -01 Jan16
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
  script_oid("1.3.6.1.4.1.25623.1.0.807034");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2016-0472", "CVE-2016-0467", "CVE-2016-0461", "CVE-2016-0499",
                "CVE-2015-4923", "CVE-2015-4921", "CVE-2015-4900", "CVE-2015-4888",
                "CVE-2015-4873", "CVE-2015-4863", "CVE-2015-4796", "CVE-2015-4794",
                "CVE-2016-0690", "CVE-2016-0681", "CVE-2016-0691", "CVE-2016-3454",
                "CVE-2016-3609", "CVE-2016-3506", "CVE-2016-3489", "CVE-2016-3484");
  script_bugtraq_id(77177, 77197, 77183, 77175, 77193, 77189, 91890, 91867, 91874, 91842);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-01-22 13:02:26 +0530 (Fri, 22 Jan 2016)");
  script_name("Oracle Database Server Multiple Unspecified Vulnerabilities -01 Jan16");

  script_tag(name:"summary", value:"This host is running  Oracle Database Server
  and is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple
  unspecified vulnerabilities.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  authenticated attackers to affect confidentiality, integrity, and availability
  via unknown vectors.");

  script_tag(name:"affected", value:"Oracle Database Server versions
  11.2.0.4, 12.1.0.1, and 12.1.0.2");

  script_tag(name:"solution", value:"Apply the patchesfrom the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html");
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

if(dbVer =~ "^(12\.1|11\.2)")
{
  if(version_is_equal(version:dbVer, test_version:"11.2.0.4") ||
     version_is_equal(version:dbVer, test_version:"12.1.0.1") ||
     version_is_equal(version:dbVer, test_version:"12.1.0.2"))
  {
    report = report_fixed_ver(installed_version:dbVer, fixed_version:"Apply the appropriate patch");
    security_message(data:report, port:dbPort);
    exit(0);
  }
}

exit(99);
