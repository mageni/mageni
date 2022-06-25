##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_nero_showtime_remote_bof_vuln_900410.nasl 12602 2018-11-30 14:36:58Z cfischer $
# Description: Nero ShowTime 'm3u' File Remote Buffer Overflow Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.900410");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-12-10 17:58:14 +0100 (Wed, 10 Dec 2008)");
  script_cve_id("CVE-2008-7079");
  script_bugtraq_id(32446);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("Denial of Service");
  script_name("Nero ShowTime 'm3u' File Remote Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://milw0rm.com/exploits/7207");
  script_xref(name:"URL", value:"http://secunia.com/Advisories/32850");

  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application.");

  script_tag(name:"affected", value:"Nero ShowTime 5.0.15.0 and prior on all Windows platforms.");

  script_tag(name:"insight", value:"This error is due to inadequate boundary checks on user supplied input.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is installed with Nero Showtime and is prone to
  'm3u' File Remote Buffer Overflow Vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

neroExe = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                               "\App Paths\ShowTime.exe",
                          item:"Path");
if(neroExe)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:neroExe);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:neroExe);
  showtime = file + "ShowTime.exe";
  showtime = GetVer(file:showtime, share:share);
  {
    pattern = "^([0-4]\..*|5\.0(\.[0-9](\..*)?|\.1[0-4](\..*)?|\.15(\.0)?)?)";
    if(egrep(pattern:pattern,string:showtime)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
