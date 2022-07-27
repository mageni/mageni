###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_security_essentials_rce_vuln_jul17.nasl 12021 2018-10-22 14:54:51Z mmartin $
#
# Microsoft Security Essentials Remote Code Execution Vulnerability Jul17
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811492");
  script_version("$Revision: 12021 $");
  script_cve_id("CVE-2017-8558");
  script_bugtraq_id(99262);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 16:54:51 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-14 14:07:22 +0530 (Fri, 14 Jul 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Security Essentials Remote Code Execution Vulnerability Jul17");

  script_tag(name:"summary", value:"This host is installed with Security
  Essentials and is prone to remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the Microsoft Malware
  Protection Engine does not properly scan a specially crafted file leading to
  memory corruption.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code in the security context of the LocalSystem account and
  take control of the system. An attacker could then install programs. View, change,
  or delete data or create new accounts with full user rights.");

  script_tag(name:"affected", value:"Microsoft Security Essentials");

  script_tag(name:"solution", value:"Microsoft Malware Protection Engine's built-in
  mechanism for the automatic detection and deployment of updates will apply the
  update within 48 hours of release.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/2510781");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8558");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\Microsoft Antimalware";
if(!registry_key_exists(key:key)){
  exit(0);
}

def_version = registry_get_sz(key:"SOFTWARE\Microsoft\Microsoft Antimalware\Signature Updates",
                              item:"EngineVersion");
if(!def_version){
  exit(0);
}

##First version of the Microsoft Malware Protection Engine with this vulnerability addressed
if(version_is_less(version:def_version, test_version:"1.1.13903.0"))
{
   report = 'Installed version : ' + def_version + '\n' +
            'Vulnerable range: Less than 1.1.13903.0';
   security_message(data:report);
   exit(0);
}
exit(0);
