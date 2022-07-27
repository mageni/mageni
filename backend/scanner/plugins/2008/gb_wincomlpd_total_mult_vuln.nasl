###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wincomlpd_total_mult_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# WinComLPD Total Multiple Vulnerabilities
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800063");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-11-26 16:25:46 +0100 (Wed, 26 Nov 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5158", "CVE-2008-5159", "CVE-2008-5176");
  script_bugtraq_id(27614);
  script_name("WinComLPD Total Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://secunia.com/advisories/28763");
  script_xref(name:"URL", value:"http://aluigi.org/adv/wincomalpd-adv.txt");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/0410");

  script_tag(name:"impact", value:"Successful exploitation could allow execution of arbitrary code
  or crashing the remote wincomlpd service by simply using negative values like
  0x80/0xff for the 8 bit numbers and 0x8000/0xffff for the data blocks.");

  script_tag(name:"affected", value:"WinCom LPD Total 3.0.2.623 and prior on Windows.");

  script_tag(name:"insight", value:"The issues are due to,

  - an error in Line Printer Daemon Service (LPDService.exe), when processing
  print jobs with an overly long control file on default TCP port 515/13500.

  - an error in authentication checks in the Line Printer Daemon (LPD).");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is installed with WinComLPD Total and is prone to buffer
  overflow and authentication bypass vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

key = "SYSTEM\CurrentControlSet\Services\LPDService";
if(!registry_key_exists(key:key)){
  exit(0);
}

lpdVer = registry_get_sz(key:key, item:"ImagePath");
if(!lpdVer){
  exit(0);
}

share = ereg_replace(pattern:"([a-zA-Z]):.*", replace:"\1$", string:lpdVer);
file =  ereg_replace(pattern:"[a-zA-Z]:(.*)", replace:"\1", string:lpdVer);

lpdVer = GetVer(file:file, share:toupper(share));
if(!lpdVer){
  exit(0);
}

if(version_is_less_equal(version:lpdVer, test_version:"3.0.2.623")){
  report = report_fixed_ver(installed_version:lpdVer, fixed_version:"WillNotFix");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);