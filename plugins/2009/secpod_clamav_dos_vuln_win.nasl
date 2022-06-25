###############################################################################
# OpenVAS Vulnerability Test
#
# ClamAV Denial of Service Vulnerability (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900546");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1371", "CVE-2009-1372");
  script_bugtraq_id(34446);
  script_name("ClamAV Denial of Service Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34612/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/0985");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_detect_win.nasl");
  script_mandatory_keys("ClamAV/Win/Ver");
  script_tag(name:"impact", value:"Attackers can exploit this issue by executing arbitrary code via a crafted
  URL in the context of affected application, and can cause denial of service.");
  script_tag(name:"affected", value:"ClamAV before 0.95.1 on Windows.");
  script_tag(name:"insight", value:"- Error in CLI_ISCONTAINED macro in libclamav/others.h while processing
    malformed files packed with UPack.

  - Buffer overflow error in cli_url_canon() function in libclamav/phishcheck.c
    while handling specially crafted URLs.");
  script_tag(name:"solution", value:"Upgrade to ClamAV 0.95.1.");
  script_tag(name:"summary", value:"The host is installed with ClamAV and is prone to Denial of Service
  Vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

avVer = get_kb_item("ClamAV/Win/Ver");
if(!avVer)
  exit(0);

if(version_is_less(version:avVer, test_version:"0.95.1")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
