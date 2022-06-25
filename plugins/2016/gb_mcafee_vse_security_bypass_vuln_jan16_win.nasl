##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_vse_security_bypass_vuln_jan16_win.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# McAfee VirusScan Enterprise Security Bypass Vulnerability Jan16 (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mcafee:virusscan_enterprise";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806964");
  script_version("$Revision: 12313 $");
  script_cve_id("CVE-2015-8577");
  script_bugtraq_id(78810);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-01-18 14:28:24 +0530 (Mon, 18 Jan 2016)");
  script_name("McAfee VirusScan Enterprise Security Bypass Vulnerability Jan16 (Windows)");

  script_tag(name:"summary", value:"This host is installed with McAfee VirusScan
  Enterprise and is prone to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as buffer overflow
  protection feature allocates memory with read, write, execute permissions at
  predictable addresses 32-bit platforms when protecting another application.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass the DEP and ASLR protection mechanisms via unspecified vectors.");

  script_tag(name:"affected", value:"McAfee VirusScan Enterprise versions before
  8.8 Patch 6 on Windows 32-bit platforms.");

  script_tag(name:"solution", value:"Upgrade to McAfee VirusScan Enterprise
  version 8.8 Patch 6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10142");
  script_xref(name:"URL", value:"http://blog.ensilo.com/the-av-vulnerability-that-bypasses-mitigations");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mcafee_virusscan_enterprise_detect_win.nasl");
  script_mandatory_keys("McAfee/VirusScan/Win/Ver");

  script_xref(name:"URL", value:"http://www.mcafee.com");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x64" >< os_arch){
  exit(0);
}

if(!mcafVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:mcafVer, test_version:"8.8.0.1445"))
{
  report = 'Installed version: ' + mcafVer + '\n' +
           'Fixed version:     ' + "8.8 patch 6 (8.8.0.1445)" + '\n';
  security_message(data:report);
  exit(0);
}

exit(99);