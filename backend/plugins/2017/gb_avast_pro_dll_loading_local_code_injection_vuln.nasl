##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avast_pro_dll_loading_local_code_injection_vuln.nasl 12021 2018-10-22 14:54:51Z mmartin $
#
# Avast Pro DoubleAgent Attack Local Code Injection Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

CPE = "cpe:/a:avast:avast_pro_antivirus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810900");
  script_version("$Revision: 12021 $");
  script_cve_id("CVE-2017-5567");
  script_bugtraq_id(97017);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 16:54:51 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-05 10:13:58 +0530 (Wed, 05 Apr 2017)");
  script_name("Avast Pro DoubleAgent Attack Local Code Injection Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Avast Pro
  and is prone to local code injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the product do not
  use the Protected Processes feature, and therefore an attacker can enter an
  arbitrary Application Verifier Provider DLL under Image File Execution Options
  in the registry. The self-protection mechanism is intended to block all local
  processes (regardless of privileges) from modifying Image File Execution Options
  for this producti.This mechanism can be bypassed by an attacker who
  temporarily renames Image File Execution Options during the attack.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attacker to execute arbitrary code in the context of the system running the
  affected application. This can also result in the attacker gaining complete
  control of the affected application.");

  script_tag(name:"affected", value:"Avast Pro versions prior to 17.0");

  script_tag(name:"solution", value:"Upgrade to Avast Pro version
  17.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://forum.avast.com/index.php?topic=199290.0");
  script_xref(name:"URL", value:"http://feeds.security-database.com/~r/Last100Alerts/~3/M6mwzAVFo-U/detail.php");
  script_xref(name:"URL", value:"https://www.engadget.com/2017/03/21/doubleagent-attack-anti-virus-hijack-your-pc");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_avast_pro_detect.nasl");
  script_mandatory_keys("Avast/Pro_Antivirus/Win/Ver");
  script_xref(name:"URL", value:"https://www.avast.com");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!avastVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:avastVer, test_version:"17.0"))
{
  report = report_fixed_ver(installed_version:avastVer, fixed_version:"17.0");
  security_message(data:report);
  exit(0);
}

exit(99);
