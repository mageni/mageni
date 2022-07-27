###############################################################################
# OpenVAS Vulnerability Test
#
# MS Windows Client/Server Run-time Subsystem Privilege Escalation Vulnerability (2646524)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2012-02-09
#  - Used Wmi function to get locale information.
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
  script_oid("1.3.6.1.4.1.25623.1.0.902499");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2012-0005");
  script_bugtraq_id(51270);
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-01-11 08:42:52 +0530 (Wed, 11 Jan 2012)");
  script_name("MS Windows Client/Server Run-time Subsystem Privilege Escalation Vulnerability (2646524)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl", "gb_wmi_access.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("WMI/access_successful", "SMB/registry_enumerated");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47479/");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2646524");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2012/ms12-003");

  script_tag(name:"impact", value:"Successful exploitation could allow attacker to execute arbitrary code with
  system-level privileges. Successfully exploiting this issue will result in
  the complete compromise of affected computers.");

  script_tag(name:"affected", value:"Microsoft Windows XP Service Pack 3 and prior.

  Microsoft Windows 2003 Service Pack 2 and prior.

  Microsoft Windows Vista Service Pack 2 and prior.

  Microsoft Windows Server 2008 Service Pack 2 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS12-003.");

  script_tag(name:"insight", value:"The flaw is due to an error in the Client/Server Run-time Subsystem
  (CSRSS) when processing specially crafted sequences of unicode characters.

  NOTE : This vulnerability can only be exploited on systems configured with
  a Chinese, Japanese or Korean system locale.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("wmi_os.inc");
include("smb_nt.inc");
include("wmi_misc.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( hotfix_check_sp( xp:4, win2003:3, winVista:3, win2008:3 ) <= 0 ) exit( 0 );

## MS12-003 Hotfix (2646524)
if( hotfix_missing( name:"2646524" ) == 0 ) exit( 0 );

host    = get_host_ip();
usrname = get_kb_item( "SMB/login" );
passwd  = get_kb_item( "SMB/password" );
if( ! host || ! usrname || ! passwd ) exit( 0 );
domain  = get_kb_item( "SMB/domain" );
if( domain ) usrname = domain + '\\' + usrname;

handle = wmi_connect( host:host, username:usrname, password:passwd );
if( ! handle ) exit( 0 );

windows_info = wmi_os_all( handle:handle );
wmi_close( wmi_handle:handle );
if( ! windows_info ) exit( 0 );

## Chinese = 0404, 0804, 0C04, 1004, 1404
## Japanese = 0411
## Korean = 0412
if( "Locale = 0404" >< windows_info || "Locale = 0804" >< windows_info ||
    "Locale = 0C04" >< windows_info || "Locale = 1004" >< windows_info ||
    "Locale = 1404" >< windows_info || "Locale = 0411" >< windows_info ||
    "Locale = 0412" >< windows_info ) {

  sysPath = smb_get_systemroot();
  if( ! sysPath ) exit( 0 );

  sysVer = fetch_file_version( sysPath:sysPath, file_name:"system32\winsrv.dll" );
  if( sysVer ) {
    if( hotfix_check_sp( xp:4 ) > 0 ) {
      if( version_is_less( version:sysVer, test_version:"5.1.2600.6179" ) ) {
        security_message( port:0 );
        exit( 0 );
      }
      exit( 99 );
    }

    else if( hotfix_check_sp( win2003:3 ) > 0 ) {
      if( version_is_less( version:sysVer, test_version:"5.2.3790.4940" ) ) {
        security_message( port:0 );
        exit( 0 );
      }
      exit( 99 );
    }

    else if( hotfix_check_sp( winVista:3, win2008:3 ) > 0 ) {
      if( version_in_range( version:sysVer, test_version:"6.0.6002.18000", test_version2:"6.0.6002.18544" ) ||
          version_in_range( version:sysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22746" ) ) {
        security_message( port:0 );
        exit( 0 );
      }
    }
  }
}

exit( 99 );
