###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Services Remote Code Execution vulnerability (2834052)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:microsoft:sharepoint_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903325");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2013-1330", "CVE-2013-3179", "CVE-2013-3180", "CVE-2013-0081",
                "CVE-2013-1315");
  script_bugtraq_id(62221, 62227, 62254, 62205, 62167);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2013-10-09 15:37:45 +0530 (Wed, 09 Oct 2013)");
  script_name("Microsoft Office Services Remote Code Execution vulnerability (2834052)");

  script_tag(name:"summary", value:"This host is missing an important security update according to Microsoft
  Bulletin MS13-067.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"insight", value:"Multiple Flaws are due to,

  - An error when handling an unassigned workflow can be exploited to cause the
  W3WP process to stop responding via a specially crafted URL.

  - An error related to MAC exists when handling unassigned workflows.

  - Input passed via the 'ms-descriptionText > ctl00_PlaceHolderDialogBodySection
  _PlaceHolderDialogBodyMainSection_ValSummary' parameter related to metadata
  storage assignment of the BDC permission management within the 'Sharepoint
  Online Cloud 2013 Service' section is not properly sanitised before being used.

  - Certain unspecified input is not properly sanitised before being returned to
  the user.

  - Multiple unspecified errors.");
  script_tag(name:"affected", value:"Excel Services on Microsoft SharePoint Server 2007

  Excel Services on Microsoft SharePoint Server 2010

  Word Automation Services on Microsoft SharePoint Server 2010");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct script insertion
  attacks, cause a DoS (Denial of Service), and compromise a vulnerable system.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54741");
  script_xref(name:"URL", value:"http://www.vulnerability-lab.com/get_content.php?id=812");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/MS13-067");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/SharePoint/Server/Ver");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms13-067");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
shareVer = infos['version'];
path = infos['location'];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

## SharePoint Server 2010 (wosrv & coreserver)
if(shareVer =~ "^14\..*")
{
  dllVer = fetch_file_version(sysPath:path, file_name:"\14.0\Bin\Xlsrv.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7104.4999"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  dllVer2 = fetch_file_version(sysPath:path,
            file_name:"\14.0\WebServices\WordServer\Core\WdsrvWorker.dll");
  if(dllVer2)
  {
    if(version_in_range(version:dllVer2, test_version:"14.0", test_version2:"14.0.7104.4999"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

## SharePoint Server 2007 (wosrv & coreserver)
if(shareVer =~ "^12\..*")
{
  dllVer = fetch_file_version(sysPath:path, file_name:"\12.0\Bin\Xlsrv.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6676.4999"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

exit(99);