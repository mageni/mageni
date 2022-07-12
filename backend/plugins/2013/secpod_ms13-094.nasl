###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Outlook Information Disclosure Vulnerability (2894514)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903413");
  script_version("2019-05-21T06:50:08+0000");
  script_cve_id("CVE-2013-3905");
  script_bugtraq_id(63603);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-21 06:50:08 +0000 (Tue, 21 May 2019)");
  script_tag(name:"creation_date", value:"2013-11-13 09:27:15 +0530 (Wed, 13 Nov 2013)");
  script_name("Microsoft Outlook Information Disclosure Vulnerability (2894514)");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-094.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"insight", value:"The flaw is due to an error during the expansion of the S/MIME certificate
  metadata when validating the X.509 certificate chain and can be exploited
  to gain knowledge IP addresses and open TCP ports from the host and the
  connected LAN via a specially crafted S/MIME certificate sent in an email.");

  script_tag(name:"affected", value:"Microsoft Outlook 2013

  Microsoft Outlook 2007 Service Pack 3 and prior

  Microsoft Outlook 2010 Service Pack 2 and prior.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to disclose certain
  sensitive information.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55574");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1029328");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2825644");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2837597");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2837618");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-094");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Outlook/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

outlookVer = get_kb_item("SMB/Office/Outlook/Version");
if(outlookVer && outlookVer =~ "^1[45]\.")
{
  if(version_in_range(version:outlookVer, test_version:"14.0", test_version2:"14.0.7109.4999") ||
     version_in_range(version:outlookVer, test_version:"15.0", test_version2:"15.0.4551.1003"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

if(outlookVer && outlookVer =~ "^12\.")
{
  ## Office outlook
  outlookFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\App Paths\OUTLOOK.EXE", item:"Path");
  if(outlookFile)
  {
    outlookVer = fetch_file_version(sysPath:outlookFile, file_name:"Exsec32.dll");
    if(outlookVer)
    {
      if(version_in_range(version:outlookVer, test_version:"12.0", test_version2:"12.0.6685.4999")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
  }
}
