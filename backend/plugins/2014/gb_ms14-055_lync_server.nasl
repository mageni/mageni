###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Lync Server Remote Denial of Service Vulnerability (2990928)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804762");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2014-4068", "CVE-2014-4070", "CVE-2014-4071");
  script_bugtraq_id(69586, 69579, 69592);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2014-09-10 11:42:19 +0530 (Wed, 10 Sep 2014)");
  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Microsoft Lync Server Remote Denial of Service Vulnerability (2990928)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS14-055.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An unspecified error when handling exceptions.

  - Certain unspecified input is not properly sanitised before being returned
    to the user.

  - Another unspecified error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct cross-site scripting attacks and cause a DoS (Denial of Service).");

  script_tag(name:"affected", value:"Microsoft Lync Server 2010,

  Microsoft Lync Server 2013");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://secunia.com/advisories/60984");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS14-055");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_lync_server_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Lync/Server/Name", "MS/Lync/Server/path");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms14-055");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

ms_lync_name = get_kb_item("MS/Lync/Server/Name");
if(!ms_lync_name){
  exit(0);
}

if("Microsoft Lync Server 2010" >< ms_lync_name)
{
  ms_lync_path = get_kb_item("MS/Lync/Server/path");
  if(ms_lync_path)
  {
    wrtces = "\Server\Core\WRTCES.dll";

    wrtces_ver = fetch_file_version(sysPath:ms_lync_path, file_name:wrtces);
    if(wrtces_ver)
    {
      if(version_in_range(version:wrtces_ver, test_version:"4.0", test_version2:"4.0.7577.229"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }

    workflow = "\Application Host\Applications\Response Group\Microsoft.Rtc.Acd.Workflow.dll";

    workflow_ver = fetch_file_version(sysPath:ms_lync_path, file_name:workflow);
    if(workflow_ver)
    {
      if(version_in_range(version:workflow_ver, test_version:"4.0", test_version2:"4.0.7577.275"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}


if("Microsoft Lync Server 2013" >< ms_lync_name)
{
  ms_lync_path = get_kb_item("MS/Lync/Server/path");
  if(ms_lync_path)
  {
    sipstack = "\Server\Core\SIPStack.dll";

    sip_ver = fetch_file_version(sysPath:ms_lync_path, file_name:sipstack);
    if(sip_ver)
    {
      if(version_in_range(version:sip_ver, test_version:"5.0", test_version2:"5.0.8308.802"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }

    workflow = "\Application Host\Applications\Response Group\Microsoft.Rtc.Acd.Workflow.dll";

    workflow_ver = fetch_file_version(sysPath:ms_lync_path, file_name:workflow);
    if(workflow_ver)
    {
      if(version_in_range(version:workflow_ver, test_version:"5.0", test_version2:"5.0.8308.802"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }

    resources = "\Deployment\de-DE\Deploy.resources.dll";

    resources_ver = fetch_file_version(sysPath:ms_lync_path, file_name:resources);
    if(resources_ver)
    {
      if(version_in_range(version:resources_ver, test_version:"5.0", test_version2:"5.0.8308.419"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }

    autodiscover = "\Web Components\Autodiscover\Ext\Bin\microsoft.rtc.internal.autodiscover.dll";

    autodiscover_ver = fetch_file_version(sysPath:ms_lync_path, file_name:autodiscover);
    if(autodiscover_ver)
    {
      if(version_in_range(version:autodiscover_ver, test_version:"5.0", test_version2:"5.0.8308.725"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
