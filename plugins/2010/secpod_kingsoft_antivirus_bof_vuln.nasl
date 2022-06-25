###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_kingsoft_antivirus_bof_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# Kingsoft Antivirus 'kavfm.sys' Buffer overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902302");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_cve_id("CVE-2010-3396");
  script_bugtraq_id(43173);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Kingsoft Antivirus 'kavfm.sys' Buffer overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41393");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14987/");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaw exists due to an error in the 'kavfm.sys' driver when
processing 'IOCTLs'. This can be exploited to corrupt kernel memory and potentially
execute arbitrary code with escalated privileges via a specially crafted
0x80030004 IOCTL.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Kingsoft Antivirus and is prone
to buffer overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
arbitrary code with SYSTEM-level privileges and completely compromise the
affected computer. Failed exploit attempts will result in a denial-of-service
condition.");
  script_tag(name:"affected", value:"Kingsoft Antivirus 2010.04.26.648 and prior");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Kingsoft")){
  exit(0);
}
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" +
                   "Kingsoft Internet Security";
if(!registry_key_exists(key:key)){
  exit(0);
}

ksantName = registry_get_sz(key:key, item:"DisplayName");

if("Kingsoft AntiVirus" >< ksantName)
{
  ksantPath = registry_get_sz(key:key + item, item:"DisplayIcon");
  if(!isnull(ksantPath))
  {
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:ksantPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:ksantPath);

    ksantVer = GetVer(file:file, share:share);
    if(ksantVer != NULL)
    {
      if(version_is_less_equal(version:ksantVer, test_version:"2010.04.26.648")){
        security_message( port: 0, data: "The target host was found to be vulnerable" ) ;
      }
    }
  }
}
