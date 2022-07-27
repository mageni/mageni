###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_f-prot_av_sec_bypass_vuln_lin.nasl 12673 2018-12-05 15:02:55Z cfischer $
#
# F-PROT AntiVirus Security Bypass Vulnerability (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.900555");
  script_version("$Revision: 12673 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 16:02:55 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-06-01 09:35:57 +0200 (Mon, 01 Jun 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1783");
  script_bugtraq_id(34896);
  script_name("F-PROT AntiVirus Security Bypass Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50427");
  script_xref(name:"URL", value:"http://blog.zoller.lu/2009/04/advisory-f-prot-frisk-cab-bypass.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("gb_f-prot_av_detect_lin.nasl");
  script_mandatory_keys("F-Prot/AV/Linux/Ver");
  script_tag(name:"impact", value:"Attackers can exploit this issue to bypass the malware detection and
  to execute arbitrary code.");
  script_tag(name:"affected", value:"F-PROT AV version 6.0.2 and prior on Linux.");
  script_tag(name:"insight", value:"The flaw is due to an error in the file parsing engine while
  processing specially crafted CAB files.");
  script_tag(name:"solution", value:"Upgrade to F-PROT AV version 6.0.3 or later");
  script_tag(name:"summary", value:"The host is installed with F-PROT AntiVirus and is prone to
  Security Bypass vulnerability.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.f-prot.com/");
  exit(0);
}


include("version_func.inc");

avVer = get_kb_item("F-Prot/AV/Linux/Ver");
if(!avVer){
  exit(0);
}

if(version_is_less_equal(version:avVer, test_version:"6.2.1.4252")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
