###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_security_scan_plus_arbitrary_cmd_exec_vuln.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# McAfee Security Scan Plus Arbitrary Command Execution Vulnerability (Windows)
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

CPE = "cpe:/a:intel:mcafee_security_scan_plus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810825");
  script_version("$Revision: 11977 $");
  script_cve_id("CVE-2016-8026");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-22 11:47:02 +0530 (Wed, 22 Mar 2017)");
  script_name("McAfee Security Scan Plus Arbitrary Command Execution Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with McAfee Security
  Scan Plus and is prone to arbitrary command execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified
  vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  authenticated users to gain elevated privileges via unspecified vectors.");

  script_tag(name:"affected", value:"McAfee Security Scan Plus version prior
  to 3.11.474.2");

  script_tag(name:"solution", value:"Upgrade to McAfee Security scan plus
  3.11.474.2.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://service.mcafee.com/webcenter/portal/cp/home/articleview?articleId=TS102614");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mcafee_security_scan_plus_detect.nasl");
  script_mandatory_keys("McAfee/SecurityScanPlus/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!msspVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:msspVer, test_version:"3.11.474.2"))
{
  report = report_fixed_ver(installed_version:msspVer, fixed_version:"3.11.474.2");
  security_message(data:report);
  exit(0);
}
