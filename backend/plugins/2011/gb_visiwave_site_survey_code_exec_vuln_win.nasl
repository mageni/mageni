###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_visiwave_site_survey_code_exec_vuln_win.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# VisiWave Site Survey Arbitrary Code Execution Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802101");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_cve_id("CVE-2011-2386");
  script_bugtraq_id(47948);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("VisiWave Site Survey Arbitrary Code Execution Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44636");
  script_xref(name:"URL", value:"http://www.visiwave.com/blog/index.php?/archives/4-Version-2.1.9-Released.html");
  script_xref(name:"URL", value:"http://www.stratsec.net/Research/Advisories/VisiWave-Site-Survey-Report-Trusted-Pointer-(SS-20");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaw exists due to an error when processing report files and can be
  exploited to perform a virtual function call into an arbitrary memory location
  via a specially crafted 'Type' property.");
  script_tag(name:"solution", value:"Upgrade to VisiWave Site Survey version 2.1.9 or later.");
  script_tag(name:"summary", value:"This host is installed with VisiWave Site Survey and is prone to
  arbitrary code execution vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code.");
  script_tag(name:"affected", value:"VisiWave Site Survey version prior to 2.1.9");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.visiwave.com/index.php/ScrInfoDownload.html");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VisiWaveSiteSurvey";

if(!registry_key_exists(key:key)){
  exit(0);
}

visiName = registry_get_sz(key:key, item:"DisplayName");
if("VisiWave Site Survey" >< visiName)
{
  visiPath = registry_get_sz(key:key + item, item:"UninstallString");

  if(!isnull(visiPath))
  {
    visiPath = ereg_replace(pattern:'\"(.*)\"', replace:"\1", string:visiPath);
    visiVer = fetch_file_version(sysPath:visiPath);

    if(visiVer != NULL)
    {
      if(version_is_less(version:visiVer, test_version:"2.1.9")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
  }
}
