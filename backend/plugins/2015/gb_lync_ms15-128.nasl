###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Lync Remote Code Execution Vulnerabilities (3104503)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806181");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2015-6106", "CVE-2015-6107", "CVE-2015-6108");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-12-09 19:52:06 +0530 (Wed, 09 Dec 2015)");
  script_name("Microsoft Lync Remote Code Execution Vulnerabilities (3104503)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-128.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws exist due to improper handling
  of JavaScript content.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  remote attacker information disclosure if an attacker invites a target user to
  an instant message session and then sends that user a message containing specially
  crafted JavaScript content.");

  script_tag(name:"affected", value:"Microsoft Lync 2010
  Microsoft Lync 2013");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114351");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115871");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-128");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "secpod_ms_lync_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Lync/Installed");

  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(get_kb_item("MS/Lync/Ver"))
{
  path = get_kb_item("MS/Lync/path");

  ## For MS Lync Basic
  if(!path){
    path = get_kb_item("MS/Lync/Basic/path");
  }

  if(path)
  {
    foreach ver (make_list("", "OFFICE14", "OFFICE15"))
    {
      commVer = fetch_file_version(sysPath:path + ver, file_name:"Rtmpltfm.dll");
      if(commVer)
      {
        if(commVer =~ "^4"){
           Vulnerable_range  =  "4.0.7577.4485";
        }
        else if(commVer =~ "^5"){
          Vulnerable_range  =  "5.0 - 5.0.8687.148";
        }

        if(version_in_range(version:commVer, test_version:"5.0", test_version2:"5.0.8687.148") ||
           version_in_range(version:commVer, test_version:"4.0", test_version2:"4.0.7577.4485"))
        {
          report = 'File checked:     ' + path + ver + "\Rtmpltfm.dll" + '\n' +
                   'File version:     ' + commVer  + '\n' +
                   'Vulnerable range: ' + Vulnerable_range + '\n' ;
          security_message(data:report);
          exit(0);
        }
      }
    }
  }
}
