###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_rational_rhapsody_activex_code_exec_vuln.nasl 11987 2018-10-19 11:05:52Z mmartin $
#
# IBM Rational Rhapsody BB FlashBack SDK ActiveX Control Remote Code Execution VUlnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902655");
  script_version("$Revision: 11987 $");
  script_cve_id("CVE-2011-1388", "CVE-2011-1391", "CVE-2011-1392");
  script_bugtraq_id(51184);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 13:05:52 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-29 15:57:58 +0530 (Thu, 29 Dec 2011)");
  script_name("IBM Rational Rhapsody BB FlashBack SDK ActiveX Control Remote Code Execution VUlnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47310");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47286");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71803");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/47310");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21576352");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execution of arbitrary code.");
  script_tag(name:"affected", value:"IBM Rational Rhapsody version prior to 7.6.1");
  script_tag(name:"insight", value:"The flaws are due to erros in the BB FlashBack ActiveX control
  (BBFlashBack.Recorder.dll) within the FBRecorder class when handling the
  'Start()', 'PauseAndSave()', 'InsertMarker()', 'InsertSoundToFBRAtMarker()'
  and 'TestCompatibilityRecordMode()' methods.");
  script_tag(name:"solution", value:"Upgrade to IBM Rational Rhapsody versions 7.6.1 or later");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with IBM Rational Rhapsody and is prone to
  remote code execution vulnerabilities.");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ibmrrName = registry_get_sz(key:key + item, item:"DisplayName");
  if("IBM Rational Rhapsody" >< ibmrrName)
  {
    ibmrrVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    if(ibmrrVer != NULL)
    {
      if(version_is_less(version:ibmrrVer, test_version:"7.6.1"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
