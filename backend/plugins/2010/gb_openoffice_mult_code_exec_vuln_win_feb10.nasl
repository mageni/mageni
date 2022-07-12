###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openoffice_mult_code_exec_vuln_win_feb10.nasl 14331 2019-03-19 14:03:05Z jschulte $
#
# OpenOffice Multiple Remote Code Execution Vulnerabilities - Feb10
#
# Authors:
# Veerendra G <veerendragg@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800167");
  script_version("$Revision: 14331 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:03:05 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-02-19 11:58:13 +0100 (Fri, 19 Feb 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_bugtraq_id(38218);
  script_cve_id("CVE-2009-2949", "CVE-2009-2950", "CVE-2009-3301", "CVE-2009-3302");
  script_name("OpenOffice Multiple Remote Code Execution Vulnerabilities - Feb10");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38568");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56236");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56238");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56240");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56241");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0366");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_openoffice_detect_win.nasl");
  script_mandatory_keys("OpenOffice/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation lets the attackers to cause a denial of service
  or execute arbitrary code.");
  script_tag(name:"affected", value:"OpenOffice.org versions prior to 3.2");
  script_tag(name:"insight", value:"- GIF Files in GIFLZWDecompressor:: GIFLZWDecompressor function in
    filter.vcl/lgif/decode.cxx leading to heap overflow.

  - XPM files in XPMReader::ReadXPM function in filter.vcl/ixpm/svt_xpmread.cxx
    leading to an integer overflow.

  - Microsoft Word document in filter/ww8/ww8par2.cxx leading to application
    crash or execute arbitrary code via crafted sprmTSetBrc table property
    in a Word document.");
  script_tag(name:"solution", value:"Upgrade to OpenOffice.org version 3.2 or later.");
  script_tag(name:"summary", value:"This host has OpenOffice running which is prone to multiple
  remote code execution vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

openOffVer = get_kb_item("OpenOffice/Win/Ver");
if(!openOffVer){
  exit(0);
}

if(openOffVer != NULL)
{
  if(version_is_less(version:openOffVer, test_version:"3.2")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
