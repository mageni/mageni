##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_flashget_ftp_pwd_bof_vuln_900203.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# FlashGet FTP PWD Response Remote Buffer Overflow Vulnerability.
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900203");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2008-4321");
  script_bugtraq_id(30685);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("FlashGet FTP PWD Response Remote Buffer Overflow Vulnerability");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2381");

  script_tag(name:"summary", value:"This host is running FlashGet, which is prone to Remote Buffer
  Overflow Vulnerability.");

  script_tag(name:"insight", value:"Error exist when handling overly long FTP PWD responses.");

  script_tag(name:"affected", value:"FlashGet 1.9 (1.9.6.1073) and prior versions on Windows (All).");

  script_tag(name:"solution", value:"Upgrade to FlashGet version 3.3 or later");

  script_tag(name:"impact", value:"Successful exploitation will allow execution of arbitrary
  code by tricking a user into connecting to a malicious ftp server.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.flashget.com/index_en.htm");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach entry(registry_enum_keys(key:key)) {

  # 1.8.x or older
  if("FlashGet(Jetcar)" >< entry || "FlashGet(JetCar)" >< entry) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }

  if("FlashGet" >< entry) {

    flashVer = registry_get_sz(item:"DisplayVersion", key:key + entry);

    # <= 1.9.6.1073 (1.9 series)
    if(flashVer && egrep(pattern:"^(1\.9|1\.9\.[0-5](\..*)?|1\.9\.6(\.(0?[0-9]?[0-9]?[0-9]|10[0-6][0-9]|107[0-3]))?)$", string:flashVer)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
    exit(99);
  }
}

exit(0);