##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_org_chart_remote_code_exe_vuln_900120.nasl 11570 2018-09-24 11:54:11Z cfischer $
#
# Microsoft Organization Chart Remote Code Execution Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900120");
  script_version("$Revision: 11570 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-24 13:54:11 +0200 (Mon, 24 Sep 2018) $");
  script_tag(name:"creation_date", value:"2008-09-10 17:51:23 +0200 (Wed, 10 Sep 2008)");
  script_cve_id("CVE-2008-3956");
  script_bugtraq_id(31059);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_name("Microsoft Organization Chart Remote Code Execution Vulnerability");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31059/discuss");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31059/exploit");
  script_xref(name:"URL", value:"http://www.nullcode.com.ar/ncs/crash/orgchart.htm");

  script_tag(name:"summary", value:"The host has Microsoft Organization Chart, which is prone to a
  remote code execution vulnerability.");

  script_tag(name:"insight", value:"Microsoft Organization Chart is prone to a remote code execution
  vulnerability. The flaw is due to memory access violation error when opening malicious Organization Chart document.");

  script_tag(name:"affected", value:"MS Organization Chart versions 2.0 (11.0.5614.0) and prior on Windows (all).");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"impact", value:"Enticing the victim into opening a malicious crafted
  Organization Chart document, remote attackers can crash the application or execute arbitrary
  code on the affected system within the context of the affected application.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach entry(registry_enum_keys(key:key)) {

  msOrgName = registry_get_sz(key:key + entry, item:"DisplayName");

  if(msOrgName && "Microsoft Organization Chart 2.0" >< msOrgName) {

    msOrgVer = registry_get_sz(key:key + entry, item:"DisplayVersion");

    # <= 11.0.5614.0
    if(msOrgVer && egrep(pattern:"^(([0-9]|10)\..*|11\.0\.([0-4]?[0-9]?[0-9]?[0-9]|5[0-5][0-9][0-9]|560[0-9]|561[0-4])\.0)$", string:msOrgVer)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
    exit(99);
  }
}

exit(0);