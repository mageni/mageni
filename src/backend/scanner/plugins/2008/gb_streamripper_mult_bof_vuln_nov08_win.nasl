###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_streamripper_mult_bof_vuln_nov08_win.nasl 12978 2019-01-08 14:15:07Z cfischer $
#
# Streamripper Multiple Buffer Overflow Vulnerabilities (Windows)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800146");
  script_version("$Revision: 12978 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-08 15:15:07 +0100 (Tue, 08 Jan 2019) $");
  script_tag(name:"creation_date", value:"2008-12-01 15:31:19 +0100 (Mon, 01 Dec 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4829");
  script_bugtraq_id(32356);
  script_name("Streamripper Multiple Buffer Overflow Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32562");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/3207");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful attack could lead to execution of arbitrary code by tricking a
  user into connecting to a malicious server or can even cause denial of service condition.");

  script_tag(name:"affected", value:"Streamripper Version 1.63.5 and earlier on Windows.");

  script_tag(name:"insight", value:"The flaws are due to boundary error within,

  - http_parse_sc_header() function in lib/http.c, when parsing an overly long
  HTTP header starting with Zwitterion v.

  - http_get_pls() and http_get_m3u() functions in lib/http.c, when parsing a
  specially crafted pls playlist containing an overly long entry or m3u
  playlist containing an overly long File entry.");

  script_tag(name:"solution", value:"Upgrade to Version 1.64.0 or later.");

  script_tag(name:"summary", value:"The host is installed with Streamripper, which is prone to Multiple
  Buffer Overflow Vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

srPath = registry_get_sz(item:"UninstallString", key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Streamripper");
if(!srPath){
  exit(0);
}

srFile = srPath - "Uninstall.exe" + "CHANGES";
srVer = smb_read_file(fullpath:srFile, offset:0, count:256);
srVer = eregmatch(pattern:"New for ([0-9.]+)", string:srVer);

if(srVer[1] != NULL )
{
  if(version_is_less(version:srVer[1], test_version:"1.64.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
