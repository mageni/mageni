###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_clamav_mult_dos_vuln_win.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# ClamAV 'cli_pdf()' and 'cli_scanicon()' Denial of Service Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902189");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-05-28 16:52:49 +0200 (Fri, 28 May 2010)");
  script_cve_id("CVE-2010-1639", "CVE-2010-1640");
  script_bugtraq_id(40318, 40317);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("ClamAV 'cli_pdf()' and 'cli_scanicon()' Denial of Service Vulnerabilities (Win");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39895");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58824");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1214");
  script_xref(name:"URL", value:"http://git.clamav.net/gitweb?p=clamav-devel.git;a=blob_plain;f=ChangeLog;hb=clamav-0.96.1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_detect_win.nasl");
  script_mandatory_keys("ClamAV/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a denial of service.");
  script_tag(name:"affected", value:"ClamAV version prior to 0.96.1 (1.0.26) on Windows.");
  script_tag(name:"insight", value:"The flaws are due to:

  - Errors exists within the 'cli_pdf()' function in 'libclamav/pdf.c' when
    processing certain 'PDF' files. This can be exploited to cause a crash.

  - Error exists within the 'parseicon()' function in 'libclamav/pe_icons.c'
    when processing 'PE' icons. This can be exploited to trigger an out-of-bounds
    access when reading data and potentially cause a crash.");
  script_tag(name:"solution", value:"Upgrade to ClamAV 0.96.1 or later.");
  script_tag(name:"summary", value:"This host has ClamAV installed, and is prone to multiple Denial of Service
  vulnerabilities.");
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

## ClamAV version less than 0.96.1 (1.0.26)
if(version_is_less(version:avVer, test_version:"0.96.1")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
