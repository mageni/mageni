###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_workstation_player_mult_code_exec_vuln_feb17_win.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# VMware Workstation Player Multiple Code Execution Vulnerabilities Feb17 (Windows)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:vmware:player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810536");
  script_version("$Revision: 11977 $");
  script_cve_id("CVE-2016-7081", "CVE-2016-7082", "CVE-2016-7083", "CVE-2016-7084",
                "CVE-2016-7085", "CVE-2016-7086");
  script_bugtraq_id(92935, 92934, 92940, 92941);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-03 13:26:11 +0530 (Fri, 03 Feb 2017)");
  script_name("VMware Workstation Player Multiple Code Execution Vulnerabilities Feb17 (Windows)");

  script_tag(name:"summary", value:"The host is installed with VMware Workstation
  Player and is prone to multiple code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple heap-based buffer overflows via Cortado Thinprint.

  - Multiple memory corruption vulnerabilities via Cortado Thinprint.

  - An untrusted search path vulnerability in the installer.

  - An insecure executable loading vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code and do local privilege escalation.");

  script_tag(name:"affected", value:"VMware Workstation Player 12.x before
  12.5.0 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Workstation Player version
  12.5.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  ## Exploitation is only possible if virtual printing has been enabled
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0014.html");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!vmwareVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(vmwareVer =~ "^12")
{
  if(version_is_less(version:vmwareVer, test_version:"12.5.0"))
  {
    report = report_fixed_ver(installed_version:vmwareVer, fixed_version:"12.5.0");
    security_message(data:report);
    exit(0);
  }
}
