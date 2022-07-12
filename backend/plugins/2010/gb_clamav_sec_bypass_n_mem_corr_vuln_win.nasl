###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clamav_sec_bypass_n_mem_corr_vuln_win.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# ClamAV Security Bypass And Memory Corruption Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801311");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)");
  script_cve_id("CVE-2010-0098", "CVE-2010-1311");
  script_bugtraq_id(39262);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("ClamAV Security Bypass And Memory Corruption Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39329");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/392749.php");
  script_xref(name:"URL", value:"http://git.clamav.net/gitweb?p=clamav-devel.git;a=blob_plain;f=ChangeLog;hb=clamav-0.96");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_clamav_detect_win.nasl");
  script_mandatory_keys("ClamAV/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
  restrictions.");
  script_tag(name:"affected", value:"ClamAV version before 0.96 (1.0.26) on Windows.");
  script_tag(name:"insight", value:"The flaws are due to:

  - An error in handling of 'CAB' and '7z' file formats, which allows to bypass
    virus detection via a crafted archive that is compatible with standard archive
    utilities.

  - An error in 'qtm_decompress' function in 'libclamav/mspack.c', which allows to
    crash application via a crafted CAB archive that uses the Quantum.");
  script_tag(name:"solution", value:"Upgrade to ClamAV 0.96 or later.");
  script_tag(name:"summary", value:"This host has ClamAV installed, and is prone to security bypass and
  memory corruption vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.clamav.net");
  exit(0);
}


include("version_func.inc");

avVer = get_kb_item("ClamAV/Win/Ver");
if(!avVer){
  exit(0);
}
## ClamAV version less than 0.96 (1.0.26)
if(version_is_less(version:avVer, test_version:"0.96")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
