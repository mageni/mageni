###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_fsecure_prdts_sec_bypass_vuln_lin.nasl 12690 2018-12-06 14:56:20Z cfischer $
#
# F-Secure Products Security Bypass Vulnerability (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.900363");
  script_version("$Revision: 12690 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-06 15:56:20 +0100 (Thu, 06 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-06-17 17:54:48 +0200 (Wed, 17 Jun 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1782");
  script_bugtraq_id(34849);
  script_name("F-Secure Products Security Bypass Vulnerability (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Malware");
  script_dependencies("gb_fsecure_prdts_detect_lin.nasl");
  script_mandatory_keys("F-Sec/Products/Lin/Installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35008");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50346");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1262");
  script_xref(name:"URL", value:"http://www.f-secure.com/en_EMEA/downloads");
  script_xref(name:"URL", value:"http://www.f-secure.com/en_EMEA/support/security-advisory/fsc-2009-1.html");

  script_tag(name:"impact", value:"Successful attacks can allow attackers to bypass scanning detection and
  possibly launch further attacks on the vulnerable system.");

  script_tag(name:"affected", value:"F-Secure Linux Security prior to 7.03 build 81803

  F-Secure Internet Gatekeeper for Linux prior to 3.02 build 1221

  F-Secure Anti-Virus Linux Client and Server Security 5.54 and prior");

  script_tag(name:"insight", value:"Error in the file parsing engine can be exploited to bypass the anti-virus
  scanning functionality via a specially crafted ZIP or RAR file.");

  script_tag(name:"solution", value:"Apply the update from the referenced advisory.");

  script_tag(name:"summary", value:"This host is installed with F-Secure Product and is prone to
  Security Bypass vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

fsavVer = get_kb_item("F-Sec/AV/LnxSec/Ver");
if(fsavVer)
{
  if(version_is_less(version:fsavVer, test_version:"7.03.81803"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

fslcsVer = get_kb_item("F-Sec/AV/LnxClntSec/Ver");
if(fslcsVer)
{
  if(version_is_less_equal(version:fslcsVer, test_version:"5.54"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

fslssVer = get_kb_item("F-Sec/AV/LnxSerSec/Ver");
if(fslssVer)
{
  if(version_is_less_equal(version:fslssVer, test_version:"5.54"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

fsigkVer = get_kb_item("F-Sec/IntGatekeeper/Lnx/Ver");
if(fsigkVer)
{
  if(version_is_less(version:fsigkVer, test_version:"3.02.1221")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
