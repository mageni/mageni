###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kaspersky_prdts_sec_bypass_vuln_aug09.nasl 14325 2019-03-19 13:35:02Z asteins $
#
# Kaspersky AntiVirus and Internet Security Unspecified Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.800850");
  script_version("$Revision: 14325 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:35:02 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-08-06 06:50:55 +0200 (Thu, 06 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2647");
  script_bugtraq_id(35789);
  script_name("Kaspersky AntiVirus and Internet Security Unspecified Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35978");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51986");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1998");
  script_xref(name:"URL", value:"http://www.kaspersky.com/technews?id=203038755");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_kaspersky_av_detect.nasl");
  script_mandatory_keys("Kaspersky/products/installed");
  script_tag(name:"impact", value:"Successful attacks lets the attacker to bypass security restrictions.");
  script_tag(name:"affected", value:"Kaspersky Anti-Virus/Internet Security 2010 version prior to 9.0.0.463");
  script_tag(name:"insight", value:"Issue is caused by an unspecified error which could allow an external script
  to disable the computer protection, facilitating further attacks.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to Critical Fix 1 (version 9.0.0.463).");
  script_tag(name:"summary", value:"This host is installed with Kaspersky AntiVirus or Internet Security
  and is prone to an unspecified vulnerability.");
  exit(0);
}

include("version_func.inc");

# For Kaspersky AntiVirus
kavVer = get_kb_item("Kaspersky/AV/Ver");
if(kavVer != NULL) {
  if(version_in_range(version:kavVer, test_version:"9.0",
                                      test_version2:"9.0.0.462")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

# For Kaspersky Internet Security
kisVer = get_kb_item("Kaspersky/IntNetSec/Ver");
if(kisVer != NULL) {
  if(version_in_range(version:kisVer, test_version:"9.0",
                                      test_version2:"9.0.0.462")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

exit(99);
