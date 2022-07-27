###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_player_guest_privilege_escalation_vuln_aug16_lin.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# VMware Player Guest Privilege Escalation Vulnerability Aug16 (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:vmware:player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809001");
  script_version("$Revision: 12149 $");
  script_cve_id("CVE-2015-6933");
  script_bugtraq_id(79958);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-19 11:02:52 +0530 (Fri, 19 Aug 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("VMware Player Guest Privilege Escalation Vulnerability Aug16 (Linux)");

  script_tag(name:"summary", value:"The host is installed with VMware Player
  and is prone to an important guest privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a kernel memory
  corruption vulnerability is present in the VMware Tools 'Shared Folders'
  (HGFS) feature running on Microsoft Windows.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  authenticated attacker on a guest operating system to gain elevated
  privileges on the guest operating system.");

  script_tag(name:"affected", value:"VMware Player 7.x prior to version 7.1.2
  on Linux.");

  script_tag(name:"solution", value:"Upgrade to VMware Player version
  7.1.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0001.html");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=42939");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_vmware_prdts_detect_lin.nasl");
  script_mandatory_keys("VMware/Linux/Installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!vmwareVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(vmwareVer =~ "^7\.")
{
  if(version_is_less(version:vmwareVer, test_version:"7.1.2"))
  {
    report = report_fixed_ver(installed_version:vmwareVer, fixed_version:"7.1.2");
    security_message(data:report);
    exit(0);
  }
}
