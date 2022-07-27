###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_esignal_mult_vuln.nasl 11552 2018-09-22 13:45:08Z cfischer $
#
# eSignal Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802245");
  script_version("$Revision: 11552 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 15:45:08 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)");
  script_cve_id("CVE-2011-3494", "CVE-2011-3503");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("eSignal Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45966/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17837/");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/esignal_1-adv.txt");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_esignal_detect.nasl");
  script_mandatory_keys("eSignal/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows execution of arbitrary code.");
  script_tag(name:"affected", value:"eSignal version 10.6.2425.1208 and prior.");
  script_tag(name:"insight", value:"- A boundary error in WinSig.exe when processing QUOTE files
  can be exploited to cause a stack-based buffer overflow.

  - A boundary error in WinSig.exe when processing the '<FaceName>' tag can be
  exploited to cause a heap-based buffer overflow via a specially crafted
  Time and Sales file.

  - The application loads libraries in an insecure manner and can be exploited
  to load arbitrary libraries by tricking a user into opening a QUOTE file
  located on a remote WebDAV or SMB share.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with eSignal and is prone to multiple
vulnerabilities.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

version = get_kb_item("eSignal/Win/Ver");
if(!version){
  exit(0);
}

if(version_is_less_equal(version:version, test_version:"10.6.2425.1208")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
