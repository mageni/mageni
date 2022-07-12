###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bullguard_av_priv_escal_vuln_feb15.nasl 11975 2018-10-19 06:54:12Z cfischer $
#
# BullGuard AntiVirus 'BdAgent.sys' Driver Local Privilege Escalation Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:bullguard:antivirus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805275");
  script_version("$Revision: 11975 $");
  script_cve_id("CVE-2014-9642");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:54:12 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-02-12 17:10:23 +0530 (Thu, 12 Feb 2015)");
  script_name("BullGuard AntiVirus 'BdAgent.sys' Driver Local Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"This host is installed with BullGuard
  AntiVirus and is prone to local privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in the
  BdAgent.sys driver that is triggered when handling various IOCTLs");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attacker to write data to an arbitrary memory location, leading to code
  execution with kernel-level privileges.");

  script_tag(name:"affected", value:"BullGuard AntiVirus before version 15.0.288");

  script_tag(name:"solution", value:"Upgrade to BullGuard AntiVirus version
  15.0.288 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.greyhathacker.net/?p=818");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35994");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130247");
  script_xref(name:"URL", value:"http://www.bullguard.com/about/release-notes.aspx");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_bullguard_antivirus_detect.nasl");
  script_mandatory_keys("BullGuard/AntiVirus/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!bullVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:bullVer, test_version:"15.0.288.0"))
{
  report = 'Installed version: ' + bullVer + '\n' +
           'Fixed version:     ' + '15.0.288.0' + '\n';
  security_message(data:report);
  exit(0);
}
