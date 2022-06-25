###############################################################################
# OpenVAS Vulnerability Test
#
# Novell Groupwise Client ActiveX Control Buffer Overflow Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:novell:groupwise";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800973");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2009-11-09 14:01:44 +0100 (Mon, 09 Nov 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3863");
  script_bugtraq_id(36398);
  script_name("Novell Groupwise Client ActiveX Control Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9683");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/387373.php");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_novell_prdts_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Novell/Groupwise/Client/Win/Installed");
  script_tag(name:"impact", value:"Successful expoitation will allow remote attackers to execute
arbitrary code on the affected system and may crash the client.");
  script_tag(name:"affected", value:"Novell GroupWise Client 7.0.3.1294 and prior on Windows.");
  script_tag(name:"insight", value:"A boundary error occurs in Novell Groupwise Client ActiveX
control(gxmim1.dll) while handling overly long arguments passed to the
'SetFontFace()' method.");
  script_tag(name:"summary", value:"This host is installed with Novell Groupwise Client ActiveX Control
and is prone to Buffer Overflow vulnerability.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
gcVer = infos['version'];

if(version_is_less_equal(version:gcVer, test_version:"7.0.3.1294"))
{
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion"+
                                "\App Paths\GrpWise.exe", item:"Path");
  if(dllPath == NULL){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$", string:dllPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",  string:dllPath+
                                                          "\gxmim1.dll");
  dllVer = GetVer(share:share, file:file);

  if(version_is_less_equal(version:dllVer, test_version:"7.0.3.1294"))
  {
    if(is_killbit_set(clsid:"{9796BED2-C1CF-11D2-9384-0008C7396667}") == 0){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
