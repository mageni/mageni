###############################################################################
# OpenVAS Vulnerability Test
#
# ClamAV Multiple Vulnerabilities (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800556");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-1241", "CVE-2009-1270", "CVE-2008-6680");
  script_bugtraq_id(34344, 34357);
  script_name("ClamAV Multiple Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/0934");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/04/07/6");
  script_xref(name:"URL", value:"http://blog.zoller.lu/2009/04/clamav-094-and-below-evasion-and-bypass.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_detect_win.nasl");
  script_mandatory_keys("ClamAV/Win/Ver");
  script_tag(name:"impact", value:"Remote attackers may exploit this issue to inject malicious files into the
  system which can bypass the scan engine and may cause denial of service.");
  script_tag(name:"affected", value:"ClamAV before 0.95 on Windows.");
  script_tag(name:"insight", value:"Multiple flaws are due to

  - Error in handling specially crafted RAR files which prevents the scanning
    of potentially malicious files.

  - Inadequate sanitation of files through a crafted TAR file causes clamd and
    clamscan to hang.

  - 'libclamav/pe.c' allows remote attackers to cause a denial of service
    via a crafted EXE which triggers a divide-by-zero error.");
  script_tag(name:"solution", value:"Upgrade to ClamAV 0.95 or later.");
  script_tag(name:"summary", value:"This host has ClamAV installed, and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

avVer = get_kb_item("ClamAV/Win/Ver");
if(avVer == NULL){
  exit(0);
}

if(version_is_less(version:avVer, test_version:"0.95")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
