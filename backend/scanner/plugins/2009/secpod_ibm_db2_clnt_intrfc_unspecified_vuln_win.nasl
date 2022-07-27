###############################################################################
# OpenVAS Vulnerability Test
#
# IBM DB2 Client Interfaces component Unspecified Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901076");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-12-23 08:41:41 +0100 (Wed, 23 Dec 2009)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2009-4325");
  script_bugtraq_id(37332);
  script_name("IBM DB2 Client Interfaces component Unspecified Vulnerabilities (Windows)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Databases");
  script_dependencies("secpod_ibm_db2_detect_win_900218.nasl");
  script_mandatory_keys("Win/IBM-db2/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass security restrictions.");
  script_tag(name:"affected", value:"IBM DB2 version 8.2 prior to FP18

  IBM DB2 version 9.1 prior to FP8

  IBM DB2 version 9.5 prior to FP5

  IBM DB2 version 9.7 prior to FP1");
  script_tag(name:"insight", value:"The flaw is due to an error in client interfaces component. It does
  not validate an unspecified pointer, which allows attackers to overwrite
  external memory via unknown vectors.");
  script_tag(name:"solution", value:"Update IBM DB2 8.2 FP18, 9.1 FP8, 9.5 FP5, 9.7 FP1.");
  script_tag(name:"summary", value:"The host is installed with IBM DB2 and is prone to unspecified
  vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"ftp://ftp.software.ibm.com/ps/products/db2/fixes/english-us/aparlist/db2_v97/APARLIST.TXT");
  script_xref(name:"URL", value:"ftp://ftp.software.ibm.com/ps/products/db2/fixes/english-us/aparlist/db2_v95/APARLIST.TXT");
  script_xref(name:"URL", value:"ftp://ftp.software.ibm.com/ps/products/db2/fixes/english-us/aparlist/db2_v91/APARLIST.TXT");
  script_xref(name:"URL", value:"ftp://ftp.software.ibm.com/ps/products/db2/fixes/english-us/aparlist/db2_v82/APARLIST.TXT");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=0&uid=swg24022678");
  exit(0);
}

include("version_func.inc");

ibmVer = get_kb_item("Win/IBM-db2/Ver");
if(!ibmVer)
  exit(0);

if(version_is_equal(version:ibmVer, test_version:"9.7.0.0") ||
   version_in_range(version:ibmVer, test_version:"8.1", test_version2:"8.1.17") ||
   version_in_range(version:ibmVer, test_version:"9.1", test_version2:"9.1.800.1022")||
   version_in_range(version:ibmVer, test_version:"9.5", test_version2:"9.5.500.783")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
