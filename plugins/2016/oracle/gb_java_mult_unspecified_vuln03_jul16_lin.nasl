###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Java SE Multiple Unspecified Vulnerabilities-03 July 2016 (Linux)
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

CPE = "cpe:/a:oracle:jre";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108387");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2016-3552", "CVE-2016-3587", "CVE-2016-3598", "CVE-2016-3610");
  script_bugtraq_id(91904, 91918, 92000, 91930);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2016-07-25 11:28:15 +0530 (Mon, 25 Jul 2016)");
  script_name("Oracle Java SE Multiple Unspecified Vulnerabilities-03 July 2016 (Linux)");

  script_tag(name:"summary", value:"The host is installed with Oracle Java SE
  and is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - A flaw in the Hotspot component.

  - A flaw in the JavaFX component.

  - A flaw in the Install component.

  - A flaw in the Libraries component");

  script_tag(name:"impact", value:"Successful exploitation will allow remote user
  to access and modify data on the target system, can cause denial of service
  conditions on the target system, a remote or local user can obtain elevated
  privileges on the  target system, also a local user can modify data on the
  target system.");

  script_tag(name:"affected", value:"Oracle Java SE 8 update 92 and prior
  on Linux.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Sun/Java/JRE/Linux/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

jreVer = infos['version'];
jrePath = infos['location'];

if(jreVer =~ "^(1\.8)")
{
  if(version_in_range(version:jreVer, test_version:"1.8.0", test_version2:"1.8.0.92"))
  {
    report = report_fixed_ver(installed_version:jreVer, fixed_version:"Apply the patch", install_path:jrePath);
    security_message(data:report);
    exit(0);
  }
}

exit(99);