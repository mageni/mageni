###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_internet_download_manager_bof_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# Internet Download Manager FTP Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800776");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)");
  script_cve_id("CVE-2010-0995");
  script_bugtraq_id(39822);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Internet Download Manager FTP Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39446");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2010-62/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/511060/100/0/threaded");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaw exists due to boundary error when sending certain test sequences to
  an 'FTP' server, which leads a stack-based buffer overflow by tricking a user
  into downloading a file from a specially crafted FTP URI.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to the Internet Download Manager 5.19");
  script_tag(name:"summary", value:"This host is installed with Internet Download Manager and is prone
  to buffer overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code.");
  script_tag(name:"affected", value:"Internet Download Manager version prior to 5.19");
  script_xref(name:"URL", value:"http://www.internetdownloadmanager.com/download.html");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" +
       "\Internet Download Manager";
if(!registry_key_exists(key:key)){
  exit(0);
}

idmName = registry_get_sz(key:key, item:"DisplayName");
if("Internet Download Manager" >< idmName)
{
  idmPath = registry_get_sz(key:key + item, item:"DisplayIcon");

  if(!isnull(idmPath))
  {
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:idmPath);
    fire = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:idmPath);

    idmVer = GetVer(file:fire, share:share);
    if(idmVer != NULL)
    {
      if(version_is_less(version:idmVer, test_version:"5.19.2.1")){
        security_message( port: 0, data: "The target host was found to be vulnerable" ) ;
      }
    }
  }
}
