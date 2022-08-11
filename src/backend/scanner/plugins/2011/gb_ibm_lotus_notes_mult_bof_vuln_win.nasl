###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_lotus_notes_mult_bof_vuln_win.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# IBM Lotus Notes File Viewers Multiple BOF Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801945");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-06-07 13:29:28 +0200 (Tue, 07 Jun 2011)");
  script_cve_id("CVE-2011-1213", "CVE-2011-1214", "CVE-2011-1215", "CVE-2011-1216",
                "CVE-2011-1217", "CVE-2011-1218", "CVE-2011-1512");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("IBM Lotus Notes File Viewers Multiple BOF Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44624");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/67621");
  script_xref(name:"URL", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21500034");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_ibm_lotus_notes_detect_win.nasl");
  script_mandatory_keys("IBM/LotusNotes/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code in the
  context of the user running the application.");
  script_tag(name:"affected", value:"IBM Lotus Notes Version 8.5.2 FP2 and prior on windows");
  script_tag(name:"insight", value:"The flaws are due to:

  - An error within 'xlssr.dll' when parsing a Binary File Format (BIFF)
     record  in an Excel spreadsheet.

  - An integer underflow error within 'lzhsr.dll' when parsing header
     information in a LZH archive file.

  - A boundary error within 'rtfsr.dll' when parsing hyperlink information
     in a Rich Text Format (RTF) document.

  - A boundary error within 'mw8sr.dll' when parsing hyperlink information
     in a Microsoft Office Document (DOC) file.

  - A boundary error within 'assr.dll' when parsing tag information in an
     Applix Spreadsheet.

  - An unspecified error within 'kpprzrdr.dll' when parsing Lotus Notes .prz
     file format.

  - An unspecified error within 'kvarcve.dll' when parsing Lotus Notes .zip
     file format.");
  script_tag(name:"solution", value:"Upgrade to IBM Lotus Notes 8.5.2 FP3");
  script_tag(name:"summary", value:"This host has IBM Lotus Notes installed and is prone to multiple
  buffer overflow vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ibm.com/software/lotus/products/notes/");
  exit(0);
}


include("version_func.inc");

lotusVer = get_kb_item("IBM/LotusNotes/Win/Ver");
if(!lotusVer){
 exit(0);
}

## Match main version and ignore the build version
version = eregmatch(pattern:"(([0-9]+\.[0-9]+\.[0-9]+).?([0-9]+)?)", string: lotusVer);
if(version[1] != NULL)
{
  if(version_is_less_equal(version:version[1], test_version:"8.5.2.2")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
