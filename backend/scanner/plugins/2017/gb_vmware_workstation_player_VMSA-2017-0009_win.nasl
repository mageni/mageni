###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_workstation_player_VMSA-2017-0009_win.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# Multiple VMware Workstation Products DLL Loading Local Privilege Escalation Vulnerability (Windows)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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
###############################################################################

CPE = "cpe:/a:vmware:player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107210");
  script_version("$Revision: 11874 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-30 11:31:00 +0200 (Tue, 30 May 2017)");
  script_cve_id("CVE-2017-4915", "CVE-2017-4916");

  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"registry");
  script_name("Multiple VMware Workstation Products DLL Loading Local Privilege Escalation Vulnerability (Linux)");
  script_tag(name:"summary", value:"VMware Workstation and Horizon View Client are prone to a remote code-execution
  vulnerability (Windows).");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"VMware Workstation Pro/Player contains an insecure library loading vulnerability
  via ALSA sound driver configuration files. Successful exploitation of this issue may allow unprivileged host users
  to escalate their privileges to root in a Linux host machine.");
  script_tag(name:"impact", value:"Successfully exploiting this issue allows attackers to execute arbitrary code in
  the context of the affected application. Failed exploits will result in denial-of-service conditions.");
  script_tag(name:"affected", value:"12.5.6");
  script_tag(name:"solution", value:"Update to VMWare Workstation Player 12.5.6. Please see the references or vendor
  advisory for more information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98566");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2017-0009.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("General");

  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Player/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!Ver = get_app_version(cpe:CPE)){
  exit(0);
}

if (Ver =~ "^12\."){

  if(version_is_less(version: Ver, test_version:"12.5.6")){
    report = report_fixed_ver(installed_version:Ver, fixed_version:"12.5.6");
    security_message(data:report);
    exit( 0 );
  }
}

exit ( 99 );
