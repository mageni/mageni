###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_windows_sp_mult_vuln.nasl 11973 2018-10-19 05:51:32Z cfischer $
#
# Microsoft Windows Service Pack Missing Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902909");
  script_version("$Revision: 11973 $");
  script_cve_id("CVE-1999-0662");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 07:51:32 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-03-27 12:06:13 +0530 (Tue, 27 Mar 2012)");
  script_name("Microsoft Windows Service Pack Missing Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/1233");
  script_xref(name:"URL", value:"http://www.cvedetails.com/cve/CVE-1999-0662");

  script_tag(name:"summary", value:"This host is installed Microsoft Windows
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to a system critical
  service pack not installed or is outdated or obsolete.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to compromise a vulnerable system.");

  script_tag(name:"affected", value:"Microsoft Windows 7 x32/x64 Editions SP0,

  Microsoft Windows 2K SP3 and prior,

  Microsoft Windows XP x32 Editions SP2 and prior,

  Microsoft Windows XP x64 Editions SP1 and prior,

  Microsoft Windows 2003 x32/x64 Editions SP1 and prior,

  Microsoft Windows Vista x32/x64 Editions SP1 and prior,

  Microsoft Windows Server 2008 x32/x64 Editions SP1 and prior,

  Microsoft Windows Server 2008 R2 SP0.");

  script_tag(name:"solution", value:"Apply the latest Service Pack or Upgrade to a recent Windows version.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.microsoft.com");
  exit(0);
}

include("secpod_reg.inc");

if( hotfix_check_sp( win2k:4 ) > 0 ) {
  SvPk = get_kb_item( "SMB/Win2K/ServicePack" );
  if( ! SvPk ) SvPk = "No Service Pack";
  report = "Installed Service Pack (SP): " + SvPk;
  security_message( port:0, data:report );
  exit( 0 );
}
if( hotfix_check_sp( xp:3 ) > 0 ) {
  SvPk = get_kb_item( "SMB/WinXP/ServicePack" );
  if( ! SvPk ) SvPk = "No Service Pack";
  report = "Installed Service Pack (SP): " + SvPk;
  security_message( port:0, data:report );
  exit( 0 );
}
if( hotfix_check_sp( xpx64:2 ) > 0 ) {
  SvPk = get_kb_item( "SMB/WinXPx64/ServicePack" );
  if( ! SvPk ) SvPk = "No Service Pack";
  report = "Installed Service Pack (SP): " + SvPk;
  security_message( port:0, data:report );
  exit( 0 );
}
if( hotfix_check_sp( win2003:2 ) > 0 ) {
  SvPk = get_kb_item( "SMB/Win2003/ServicePack" );
  if( ! SvPk ) SvPk = "No Service Pack";
  report = "Installed Service Pack (SP): " + SvPk;
  security_message( port:0, data:report );
  exit( 0 );
}
if( hotfix_check_sp( win2003x64:2 ) > 0 ) {
  SvPk = get_kb_item( "SMB/Win2003x64/ServicePack" );
  if( ! SvPk ) SvPk = "No Service Pack";
  report = "Installed Service Pack (SP): " + SvPk;
  security_message( port:0, data:report );
  exit( 0 );
}
if( hotfix_check_sp( winVista:2 ) > 0 ) {
  SvPk = get_kb_item( "SMB/WinVista/ServicePack" );
  if( ! SvPk ) SvPk = "No Service Pack";
  report = "Installed Service Pack (SP): " + SvPk;
  security_message( port:0, data:report );
  exit( 0 );
}
if( hotfix_check_sp( winVistax64:2 ) > 0 ) {
  SvPk = get_kb_item( "SMB/WinVistax64/ServicePack" );
  if( ! SvPk ) SvPk = "No Service Pack";
  report = "Installed Service Pack (SP): " + SvPk;
  security_message( port:0, data:report );
  exit( 0 );
}
if( hotfix_check_sp( win7:1 ) > 0 ) {
  SvPk = get_kb_item( "SMB/Win7/ServicePack" );
  if( ! SvPk ) SvPk = "No Service Pack";
  report = "Installed Service Pack (SP): " + SvPk;
  security_message( port:0, data:report );
  exit( 0 );
}
if( hotfix_check_sp( win7x64:1 ) > 0 ) {
  SvPk = get_kb_item( "SMB/Win7x64/ServicePack" );
  if( ! SvPk ) SvPk = "No Service Pack";
  report = "Installed Service Pack (SP): " + SvPk;
  security_message( port:0, data:report );
  exit( 0 );
}
if( hotfix_check_sp( win2008:2 ) > 0 ) {
  SvPk = get_kb_item( "SMB/Win2008/ServicePack" );
  if( ! SvPk ) SvPk = "No Service Pack";
  report = "Installed Service Pack (SP): " + SvPk;
  security_message( port:0, data:report );
  exit( 0 );
}
if( hotfix_check_sp( win2008x64:2 ) > 0 ) {
  SvPk = get_kb_item( "SMB/Win2008x64/ServicePack" );
  if( ! SvPk ) SvPk = "No Service Pack";
  report = "Installed Service Pack (SP): " + SvPk;
  security_message( port:0, data:report );
  exit( 0 );
}
if( hotfix_check_sp( win2008r2:1 ) > 0 ) {
  SvPk = get_kb_item( "SMB/Win2008R2/ServicePack" );
  if( ! SvPk ) SvPk = "No Service Pack";
  report = "Installed Service Pack (SP): " + SvPk;
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );