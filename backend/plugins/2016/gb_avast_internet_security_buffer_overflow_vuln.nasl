##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avast_internet_security_buffer_overflow_vuln.nasl 11903 2018-10-15 10:26:16Z asteins $
#
# Avast Internet Security Heap-Based Buffer Overflow Vulnerability
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

CPE = "cpe:/a:avast:avast_internet_security";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808055");
  script_version("$Revision: 11903 $");
  script_cve_id("CVE-2015-8620");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-15 12:26:16 +0200 (Mon, 15 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-03 18:38:06 +0530 (Fri, 03 Jun 2016)");
  script_name("Avast Internet Security Heap-Based Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Avast Internet
  Security and is prone to heap-based buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists in avast virtualization
  driver (aswSnx.sys) that handles 'Sandbox' and 'DeepScreen' functionality
  improperly.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to elevate privileges from any account type and execute code as SYSTEM.");

  script_tag(name:"affected", value:"Avast Internet Security version before
  11.1.2253");

  script_tag(name:"solution", value:"Upgrade to Avast Internet Security
  version 11.1.2253 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Feb/94");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_avast_internet_security_detect.nasl");
  script_mandatory_keys("Avast/Internet-Security/Win/Ver");
  script_xref(name:"URL", value:"https://www.avast.com");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!avastVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:avastVer, test_version:"11.1.2253"))
{
  report = report_fixed_ver(installed_version:avastVer, fixed_version:"11.1.2253");
  security_message(data:report);
  exit(0);
}
