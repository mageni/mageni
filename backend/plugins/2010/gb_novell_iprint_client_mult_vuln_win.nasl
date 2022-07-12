###############################################################################
# OpenVAS Vulnerability Test
#
# Novell iPrint Client Multiple Security Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on  2010-08-30
#  Added the releted CVE's
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

CPE = "cpe:/a:novell:iprint";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801423");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2010-08-16 09:09:42 +0200 (Mon, 16 Aug 2010)");
  script_cve_id("CVE-2010-3109", "CVE-2010-3108", "CVE-2010-3107", "CVE-2010-3106");
  script_bugtraq_id(42100);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Novell iPrint Client Multiple Security Vulnerabilities (Windows)");

  script_xref(name:"URL", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-10-06");
  script_xref(name:"URL", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-10-05");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-139/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-140/");

  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_novell_prdts_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Novell/iPrint/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code,
  delete files on a system.");
  script_tag(name:"affected", value:"Novell iPrint Client version 5.40 and prior.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Error in handling 'ienipp.ocx' ActiveX control.

  - Error within the nipplib.dll module that can be reached via the 'ienipp.ocx'
    ActiveX control with 'CLSID 36723f97-7aa0-11d4-8919-FF2D71D0D32C'.

  - Failure to verify the name of parameters passed via '<embed>' tags.

  - Error in handling plugin parameters. A long value for the operation
    parameter can trigger a stack-based buffer overflow.");
  script_tag(name:"summary", value:"The host is installed with Novell iPrint Client and is prone to
  multiple vulnerabilities.");
  script_tag(name:"solution", value:"Apply patch  *****
  NOTE : Ignore this warning, if above mentioned patch is applied already.
  *****");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://download.novell.com/Download?buildid=ftwZBxEFjIg~");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
iPrintVer = infos['version'];

if(version_is_less_equal(version:iPrintVer, test_version:"5.40"))
{
  ## Path for the ienipp.ocx file
  path = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                        item:"Install Path");
  if(!path){
    exit(0);
  }

  path = path + "\ienipp.ocx";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:path);

  ocxSize = get_file_size(share:share, file:file);
  if(ocxSize)
  {
    if(is_killbit_set(clsid:"{36723f97-7aa0-11d4-8919-FF2D71D0D32C}") == 0){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
