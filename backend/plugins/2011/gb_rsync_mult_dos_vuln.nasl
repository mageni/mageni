###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rsync_mult_dos_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Rsync Multiple Denial of Service Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801772");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_cve_id("CVE-2011-1097");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("Rsync Multiple Denial of Service Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1025256");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0792");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaws are due to

  - a memory corruption error when processing malformed file list data.

  - error while handling directory paths, '--backup-dir', filter/exclude lists.");
  script_tag(name:"solution", value:"Upgrade to rsync version 3.0.8 or later");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with Rsync and is prone to multiple denial
  of service vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to crash an affected
  application or execute arbitrary code by tricking a user into connecting
  to a malicious rsync server and using the '--recursive' and '--delete'
  options without the '--owner' option.");
  script_tag(name:"affected", value:"rsync version 3.x before 3.0.8");
  script_xref(name:"URL", value:"http://rsync.samba.org/");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" +
       "\cwRsync";
if(!registry_key_exists(key:key)){
  exit(0);
}

rsyncName = registry_get_sz(key:key, item:"DisplayName");
if("cwRsync" >< rsyncName)
{
  rsyncPath = registry_get_sz(key:key, item:"UninstallString");
  if(!isnull(rsyncPath))
  {
    rsyncPath = ereg_replace(pattern:'\"(.*)\"', replace:"\1", string:rsyncPath);
    rsyncVer = fetch_file_version(sysPath:rsyncPath);

    if(rsyncVer != NULL)
    {
      if(version_in_range(version:rsyncVer, test_version:"3.0", test_version2:"3.0.7")){
        security_message( port: 0, data: "The target host was found to be vulnerable" ) ;
      }
    }
  }
}
