###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_thunderbird_mem_crptn_vuln_jul09_win.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# Mozilla Thunderbird Memory Corruption Vulnerabilities July-09 (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900801");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-07-23 21:05:26 +0200 (Thu, 23 Jul 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2462", "CVE-2009-2463", "CVE-2009-2464",
                "CVE-2009-2465", "CVE-2009-2466");
  script_bugtraq_id(35765, 35769, 35775, 35770, 35776);
  script_name("Mozilla Thunderbird Memory Corruption Vulnerabilities July-09 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35914");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1972");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-34.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attacker to execute
arbitrary code, memory corruption, and results in Denial of Service condition.");
  script_tag(name:"affected", value:"Mozilla Thunderbird version 2.0.0.22 and prior on Windows.");
  script_tag(name:"insight", value:"The flaws are due to error in browser engine which can be
exlpoited via some of the known vectors and unspecified vectors.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is installed with Thunderbird and is prone to Remote
Code Execution vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(!tbVer){
  exit(0);
}

if(version_is_less_equal(version:tbVer, test_version:"2.0.0.22")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
