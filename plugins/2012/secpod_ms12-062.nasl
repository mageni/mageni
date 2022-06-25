###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft System Center Configuration Manager XSS Vulnerability (2741528)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902688");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2012-2536");
  script_bugtraq_id(55430);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-09-12 09:31:18 +0530 (Wed, 12 Sep 2012)");
  script_name("Microsoft System Center Configuration Manager XSS Vulnerability (2741528)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_system_center_configmgr_detect_win.nasl");
  script_mandatory_keys("MS/SMS_or_ConfigMgr/Installed");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.");
  script_tag(name:"affected", value:"Microsoft Systems Management Server 2003 SP3 and prior
  Microsoft System Center Configuration Manager 2007 SP2 R2 or R3 and prior");
  script_tag(name:"insight", value:"Input validation error due the way System Center Configuration Manager
  handles specially crafted requests, which can be exploited to insert
  arbitrary HTML and script code.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS12-062.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50497");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2741528");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/MS12-062");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-062");
  exit(0);
}


include("version_func.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

if(get_kb_item("MS/ConfigMgr/Version"))
{
  path = get_kb_item("MS/ConfigMgr/Path");
  if(path && "Could not find the install Location" >!< path)
  {
    path = path - "\AdminUI";
    path = path + "\bin\i386";
    confVer = fetch_file_version(sysPath:path, file_name:"Reportinginstall.exe");
    if(confVer)
    {
      if(version_in_range(version:confVer, test_version:"4.0", test_version2:"4.0.6487.2215"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

if(get_kb_item("MS/SMS/Version"))
{
  path = get_kb_item("MS/SMS/Path");
  if(path && "Could not find the install Location" >!< path)
  {
    path = path + "\bin\i386";
    confVer = fetch_file_version(sysPath:path, file_name:"Reportinginstall.exe");
    if(confVer)
    {
      if(version_in_range(version:confVer, test_version:"2.0", test_version2:"2.50.4253.3128"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
