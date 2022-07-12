###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_db_mult_unspecified_vuln05_jan16.nasl 12456 2018-11-21 09:45:52Z cfischer $
#
# Oracle Database Server Multiple Unspecified Vulnerabilities -05 Jan16
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
  script_oid("1.3.6.1.4.1.25623.1.0.807040");
  script_version("$Revision: 12456 $");
  script_cve_id("CVE-2014-6546", "CVE-2014-6467", "CVE-2014-6545", "CVE-2014-6453",
                "CVE-2014-6560", "CVE-2014-6455", "CVE-2014-6537", "CVE-2014-6547",
                "CVE-2014-4293", "CVE-2014-4292", "CVE-2014-4291", "CVE-2014-4290",
                "CVE-2014-4297", "CVE-2014-4296", "CVE-2014-6477", "CVE-2014-4310",
                "CVE-2014-6538", "CVE-2014-4295", "CVE-2014-4294", "CVE-2014-6563",
                "CVE-2014-6542", "CVE-2014-4298", "CVE-2014-4299", "CVE-2014-4300",
                "CVE-2014-6452", "CVE-2014-6454", "CVE-2015-0483", "CVE-2015-0457",
                "CVE-2015-4740", "CVE-2015-2629", "CVE-2015-2599", "CVE-2014-6541",
                "CVE-2014-6567", "CVE-2015-0373");
  script_bugtraq_id(70453, 70514, 70467, 70474, 70482, 70473, 70492, 70536, 70490,
                    70499, 70500, 70501, 70502, 70504, 70505, 70495, 70498, 70508,
                    70465, 70515, 70524, 70526, 70527, 70528, 70529, 74079, 74090,
                    75838, 75851, 75852, 72158, 72134, 72145);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:45:52 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-01-25 14:59:25 +0530 (Mon, 25 Jan 2016)");
  script_name("Oracle Database Server Multiple Unspecified Vulnerabilities -05 Jan16");

  script_tag(name:"summary", value:"This host is running  Oracle Database Server
  and is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple
  unspecified vulnerabilities.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  authenticated attackers to affect confidentiality, integrity, and availability
  via unknown vectors.");

  script_tag(name:"affected", value:"Oracle Database Server versions
  11.1.0.7, 11.2.0.3, 11.2.0.4, 12.1.0.1, and 12.1.0.2.");

  script_tag(name:"solution", value:"Apply the patches from the referenced advisory.");

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

if(dbVer =~ "^1[12]")
{
  if(version_is_equal(version:dbVer, test_version:"12.1.0.1") ||
     version_is_equal(version:dbVer, test_version:"12.1.0.2") ||
     version_is_equal(version:dbVer, test_version:"11.2.0.3") ||
     version_is_equal(version:dbVer, test_version:"11.2.0.4") ||
     version_is_equal(version:dbVer, test_version:"11.1.0.7"))
  {
    report = report_fixed_ver(installed_version:dbVer, fixed_version:"Apply the appropriate patch");
    security_message(data:report, port:dbPort);
    exit(0);
  }
}

exit(99);
