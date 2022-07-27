###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_microsoft_emet_rop_vuln.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# Microsoft Enhanced Mitigation Experience Toolkit (EMET) ROP Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803972");
  script_version("$Revision: 11888 $");
  script_cve_id("CVE-2013-6791");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-12-03 13:41:01 +0530 (Tue, 03 Dec 2013)");
  script_name("Microsoft Enhanced Mitigation Experience Toolkit (EMET) ROP Vulnerability");


  script_tag(name:"summary", value:"The host is installed with Microsoft Enhanced Mitigation Experience Toolkit
(EMET) and is prone to return-oriented programming (ROP) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to Microsoft Enhanced Mitigation Experience Toolkit (EMET) version
4.0 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"insight", value:"The flaw is in the application which uses predictable addresses for hooked
functions.");
  script_tag(name:"affected", value:"Microsoft Enhanced Mitigation Experience Toolkit (EMET) before 4.0");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass ASLR protection
mechanism via a return-oriented programming (ROP) attack.");

  script_xref(name:"URL", value:"http://en.nsfocus.com/2013/advisories_0620/150.html");
  script_xref(name:"URL", value:"http://blogs.technet.com/b/srd/archive/2013/06/17/emet-4-0-now-available-for-download.aspx");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_smb_windows_detect.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2458544");
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("host_details.inc");

key = "SOFTWARE\Microsoft\EMET";

if(!registry_key_exists(key:key)){
  exit(0);
}

unkey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(registry_key_exists(key:unkey))
{
  foreach item (registry_enum_keys(key:unkey))
  {
    emetName = registry_get_sz(key:unkey + item, item:"DisplayName");

    if(emetName && emetName =~ "EMET")
    {
      emetVer = registry_get_sz(key:unkey + item, item:"DisplayVersion");

      if(emetVer && version_is_less(version:emetVer, test_version:"4.0"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
