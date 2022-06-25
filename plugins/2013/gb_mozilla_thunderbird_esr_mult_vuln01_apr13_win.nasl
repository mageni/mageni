###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_thunderbird_esr_mult_vuln01_apr13_win.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Mozilla Thunderbird ESR Multiple Vulnerabilities -01 Apr13 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803469");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-0788", "CVE-2013-0791", "CVE-2013-0793", "CVE-2013-0795",
                                 "CVE-2013-0797", "CVE-2013-0799", "CVE-2013-0800");
  script_bugtraq_id(58818, 58819, 58826, 58837, 58836, 58827, 58824, 58825);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-04-08 11:48:39 +0530 (Mon, 08 Apr 2013)");
  script_name("Mozilla Thunderbird ESR Multiple Vulnerabilities -01 Apr13 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52770");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52293");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=825721");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird-ESR/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
  memory corruption, bypass certain security restrictions and compromise
  a user's system.");
  script_tag(name:"affected", value:"Mozilla Thunderbird ESR version 17.x before 17.0.5 on Windows");
  script_tag(name:"insight", value:"- Unspecified vulnerabilities in the browser engine

  - Buffer overflow in the Mozilla Maintenance Service

  - Untrusted search path vulnerability while handling dll files

  - Improper validation of address bar during history navigation

  - Integer signedness error in the 'pixman_fill_sse2' function in
    'pixman-sse2.c' in Pixman

  - Error in 'CERT_DecodeCertPackage' function in Mozilla Network Security
    Services (NSS)

  - The System Only Wrapper (SOW) implementation does not prevent use of the
    cloneNode method for cloning a protected node");
  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird ESR version 17.0.5 or later.");
  script_tag(name:"summary", value:"This host is installed with Mozilla Thunderbird ESR and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/thunderbird");
  exit(0);
}


include("version_func.inc");

tbVer = get_kb_item("Thunderbird-ESR/Win/Ver");

if(tbVer && tbVer =~ "^(17.0)")
{
  if(version_in_range(version:tbVer, test_version:"17.0", test_version2:"17.0.4"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
