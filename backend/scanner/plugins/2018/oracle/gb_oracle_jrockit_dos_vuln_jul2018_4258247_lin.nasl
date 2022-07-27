###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle JRocKit Denial of Service Vulnerability (jul2018-4258247) Linux
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:oracle:jrockit";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813734");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-2952");
  script_bugtraq_id(104765);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-07-30 14:56:48 +0530 (Mon, 30 Jul 2018)");
  script_name("Oracle JRocKit Denial of Service Vulnerability (jul2018-4258247) Linux");

  script_tag(name:"summary", value:"The host is installed with Oracle JRocKit
  and is prone to a denial-of-service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  'Concurrency' component of JRockit.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct a denial-of-service condition.");

  script_tag(name:"affected", value:"Oracle JRockit version R28.3.18 and prior");

  script_tag(name:"solution", value:"Update to Oracle JRockit R28.3.19 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://docs.oracle.com/cd/E15289_01/JRRLN/newchanged.htm#GUID-0DF372A6-33EB-4DD6-AA2D-B4822FF65C03");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html#AppendixJAVA");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_oracle_jrockit_detect_lin.nasl");
  script_mandatory_keys("JRockit/Lin/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");
include("revisions-lib.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
rocVer = infos['version'];
path = infos['location'];

if((revcomp(a:rocVer, b: "R28.0") >= 0) && (revcomp(a:rocVer, b: "R28.3.19") < 0))
{
  report = report_fixed_ver(installed_version:rocVer, fixed_version:"R28.3.19", install_path:path);
  security_message(data: report);
  exit(0);
}
exit(99);
