###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_endpoint_protection_mult_vuln_nov15.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Symantec Endpoint Protection Multiple Vulnerabilities Nov15
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
CPE = "cpe:/a:symantec:endpoint_protection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806571");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-8113", "CVE-2015-6555", "CVE-2015-6554");
  script_bugtraq_id(77494, 77495, 77585);
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-11-16 12:41:11 +0530 (Mon, 16 Nov 2015)");
  script_name("Symantec Endpoint Protection Multiple Vulnerabilities Nov15");

  script_tag(name:"summary", value:"This host is installed with Symantec
  Endpoint Protection and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An untrusted search path flaw.

  - Multiple unspecified flaws in the management console.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attacker to gain privileges, and an unauthenticated, remote attacker to do
  OS command execution, Java code execution with elevated application privileges.");

  script_tag(name:"affected", value:"Symantec Endpoint Protection (SEP) before
  version 12.1-RU6-MP3");

  script_tag(name:"solution", value:"Update to Symantec Endpoint Protection (SEP)
  version 12.1-RU6-MP3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.tenable.com/plugins/index.php?view=single&id=86873");
  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20151109_00");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

## https://en.wikipedia.org/wiki/Symantec_Endpoint_Protection#Version_history
if(isnull(sepType) &&
   version_in_range(version:sepVer, test_version:"12.1", test_version2:"12.1.6465.6200"))

{
  report = 'Installed version: ' + sepVer + '\n' +
           'Fixed version:     ' + '12.1 RU6 MP3' + '\n';
  security_message(data:report);
  exit(0);
}
