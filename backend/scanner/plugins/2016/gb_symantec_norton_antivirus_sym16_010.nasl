###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_norton_antivirus_sym16_010.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# Symantec Norton AntiVirus Decomposer Engine Multiple Parsing Vulnerabilities
#
# Authors:
# Tushar Khelge <tushar.khelge@secpod.com>
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

CPE = "cpe:/a:symantec:norton_antivirus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808511");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2016-2207", "CVE-2016-2209", "CVE-2016-2210", "CVE-2016-2211",
                "CVE-2016-3644", "CVE-2016-3645", "CVE-2016-3646");
  script_bugtraq_id(91434, 91436, 91437, 91438, 91431, 91439, 91435);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-07-04 16:11:01 +0530 (Mon, 04 Jul 2016)");
  script_name("Symantec Norton AntiVirus Decomposer Engine Multiple Parsing Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Symantec
  Norton AntiVirus and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to an error in
  Parsing of maliciously-formatted container files in Symantecs Decomposer engine.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause memory corruption, integer overflow or buffer overflow results in an
  application-level denial of service.");

  script_tag(name:"affected", value:"Symantec Norton AntiVirus NGC 22.7 and prior.");

  script_tag(name:"solution", value:"Update Symantec Norton AntiVirus
  through LiveUpdate.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160628_00");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec/Norton-AV/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sepVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Symantec Norton AntiVirus after LiveUpdate (22.7.0.76)
if(version_is_less(version:sepVer, test_version:"22.7.0.76"))
{
  report = report_fixed_ver(installed_version:sepVer, fixed_version:"22.7.0.76");
  security_message(data:report);
  exit(0);
}

