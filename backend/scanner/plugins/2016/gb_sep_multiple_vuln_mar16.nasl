###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sep_multiple_vuln_mar16.nasl 11837 2018-10-11 09:17:05Z asteins $
#
# Symantec Endpoint Protection Multiple Vulnerabilities - Mar16
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:symantec:endpoint_protection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806691");
  script_version("$Revision: 11837 $");
  script_cve_id("CVE-2015-8154", "CVE-2015-8153", "CVE-2015-8152");
  script_tag(name:"cvss_base", value:"8.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-11 11:17:05 +0200 (Thu, 11 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-04-06 16:24:51 +0530 (Wed, 06 Apr 2016)");
  script_name("Symantec Endpoint Protection Multiple Vulnerabilities - Mar16");

  script_tag(name:"summary", value:"This host is installed with Symantec
  Endpoint Protection and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An error in sysPlant.sys driver in the Application and Device Control (ADC)
    component in the client in Symantec Endpoint Protection.

  - Multiple insufficient input validation in SEPM.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary SQL commands, hijack the authentication of administrators
  and execute arbitrary code via a crafted HTML document on the affected system.");

  script_tag(name:"affected", value:"Symantec Endpoint Protection (SEP)
  before version 12.1-RU6-MP4");

  script_tag(name:"solution", value:"Update to Symantec Endpoint Protection (SEP)
  version 12.1-RU6-MP4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&amp;pvid=security_advisory&amp;year=&amp;suid=20160317_00");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec/Endpoint/Protection");
  script_xref(name:"URL", value:"http://www.symantec.com/en/in/endpoint-protection");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sepVer = get_app_version(cpe:CPE)){
  exit(0);
}

sepType = get_kb_item("Symantec/SEP/SmallBusiness");

if(isnull(sepType) &&
   version_in_range(version:sepVer, test_version:"12.1", test_version2:"12.1.6860.6399"))
{
  report = report_fixed_ver(installed_version:sepVer, fixed_version:"12.1 RU6-MP4");
  security_message(data:report);
  exit(0);
}

exit(99);
