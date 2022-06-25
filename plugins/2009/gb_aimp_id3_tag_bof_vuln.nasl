###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aimp_id3_tag_bof_vuln.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# AIMP ID3 Tag Buffer Overflow Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated to CVE-2009-3170
# - By Nikita MR <rnikita@secpod.com> On 2009-09-15 #4729
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800591");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1944", "CVE-2009-3170");
  script_name("AIMP ID3 Tag Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35295/");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9561");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8837");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50875");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2530");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_aimp_detect.nasl");
  script_mandatory_keys("AIMP/Ver");
  script_tag(name:"affected", value:"AIMP2 version 2.5.1.330 and prior.");
  script_tag(name:"insight", value:"- A boundary check error exists while processing MP3 files with
overly long ID3 tag.

  - Stack-based buffer overflow occurs when application fails to handle long
File1 argument in a '.pls' or '.m3u' playlist file.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host has AIMP2 player installed and is prone to Buffer Overflow
vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to exploit
arbitrary code in the context of the affected application.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

aimpVer = get_kb_item("AIMP/Ver");

if(aimpVer != NULL)
{
  if(version_is_less_equal(version:aimpVer, test_version:"2.5.1.330")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
