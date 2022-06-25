#################################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_java_jre_actvx_ctrl_mult_bof_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# Java JRE deploytk.dll ActiveX Control Multiple BOF Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
#################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900354");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2009-05-22 08:49:17 +0200 (Fri, 22 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1671", "CVE-2009-1672");
  script_bugtraq_id(34931);
  script_name("Java JRE deploytk.dll ActiveX Control Multiple BOF Vulnerabilities");
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"An attacker may exploit this issue to launch JRE installation and execute
  arbitrary script code on the victim's system, and can deny the service.");

  script_tag(name:"affected", value:"Sun Java JRE version 6 Update 1 to 6 Update 13 and prior
  Sun Microsystems, deploytk.dll version 6.0.130.3 and prior");

  script_tag(name:"insight", value:"Multiple buffer overflows are due to,

  - error in deploytk.dll file control while processing the setInstallerType,
    setAdditionalPackages, compareVersion, getStaticCLSID and launch method.

  - error in installLatestJRE or installJRE method in deploytk.dll control and
    it can allow attacker to launch JRE installation processes.

  - error in launch method can cause script code execution via a .jnlp URL.");

  script_tag(name:"summary", value:"This host is installed with Java JRE Deployment Toolkit ActiveX and
  is prone to multiple buffer overflow vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Sun Java JRE version 6 Update 20 or later.  Workaround:
  Set the killbit for the CLSID {CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA}");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/240797");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8665");
  script_xref(name:"URL", value:"http://www.shinnai.net/xplits/TXT_mhxRKrtrPLyAHRFNm7QR.html");
  script_xref(name:"URL", value:"http://java.sun.com");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");
if(!jreVer){
  exit(0);
}

if(version_in_range(version:jreVer, test_version:"1.6.0", test_version2:"1.6.0.13"))
{
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                            item:"Install Path");
  if(!dllPath){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                       string:dllPath + "\deploytk.dll");

  dllVer = GetVer(file:file, share:share);
  if(!dllVer){
    exit(0);
  }

  if(version_is_less_equal(version:dllVer, test_version:"6.0.130.3"))
  {
    if(is_killbit_set(clsid:"{CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA}") == 0){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

exit(99);
