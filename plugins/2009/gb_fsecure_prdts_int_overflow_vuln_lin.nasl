###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fsecure_prdts_int_overflow_vuln_lin.nasl 12690 2018-12-06 14:56:20Z cfischer $
#
# F-Secure Product(s) Integer Overflow Vulnerability (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800358");
  script_version("$Revision: 12690 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-06 15:56:20 +0100 (Thu, 06 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-03-13 14:39:10 +0100 (Fri, 13 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-6085");
  script_bugtraq_id(31846);
  script_name("F-Secure Product(s) Integer Overflow Vulnerability (Linux)");

  script_xref(name:"URL", value:"http://www.f-secure.com/security/fsc-2008-3.shtml");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32352");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Oct/1021073.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_fsecure_prdts_detect_lin.nasl");
  script_mandatory_keys("F-Sec/Products/Lin/Installed");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to craft the archive
  files with arbitrary codes and can cause integer overflow in the context of an affected application.");

  script_tag(name:"affected", value:"F-Secure Linux Security 7.01 and prior

  F-Secure Anti-Virus Linux Client/Server Security 5.54 and prior

  F-Secure Internet Gatekeeper for Linux 2.16 and prior on Linux.");

  script_tag(name:"insight", value:"The vulnerability is due to an integer overflow error while scanning
  contents of specially crafted RPM files inside the archives.");

  script_tag(name:"solution", value:"Apply the update from the referenced advisory.");

  script_tag(name:"summary", value:"This host is installed with F-Secure Product(s) and is prone to
  Integer Overflow vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

fsavVer = get_kb_item("F-Sec/AV/LnxSec/Ver");
if(fsavVer)
{
  if(version_is_less(version:fsavVer, test_version:"7.02"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

fsavVer = get_kb_item("F-Sec/AV/LnxClntSec/Ver");
if(fsavVer)
{
  if(version_is_less(version:fsavVer, test_version:"5.54.7410"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

fsavVer = get_kb_item("F-Sec/AV/LnxSerSec/Ver");
if(fsavVer)
{
  if(version_is_less(version:fsavVer, test_version:"5.54.7410"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

fsigkVer = get_kb_item("F-Sec/IntGatekeeper/Lnx/Ver");
if(fsigkVer)
{
  if(version_is_less(version:fsigkVer, test_version:"2.16.580")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
