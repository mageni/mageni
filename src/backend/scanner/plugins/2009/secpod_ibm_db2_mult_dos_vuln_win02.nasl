###############################################################################
# OpenVAS Vulnerability Test
#
# IBM DB2 Multiple DOS Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi<santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900677");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-6821", "CVE-2008-6820", "CVE-2008-2154");
  script_bugtraq_id(31058, 35409);
  script_name("IBM DB2 Multiple Vulnerabilities (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/31787");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Jun/1022319.htm");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1JR30227");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=0&uid=swg24022678");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_ibm_db2_detect_win_900218.nasl");
  script_mandatory_keys("Win/IBM-db2/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass security restrictions,
  cause a denial of service or gain elevated privileges.");
  script_tag(name:"affected", value:"IBM DB2 version 8 prior to Fixpak 17

  IBM DB2 version 9.1 prior to Fixpak 5

  IBM DB2 version 9.5 prior to Fixpak 2");
  script_tag(name:"insight", value:"The flaws are due to,

  - An unspecified error related to the DB2FMP process running
    with OS prvileges.

  - An error in INSTALL_JAR procedure  might allows remote authenticated
    users to create or overwrite arbitrary files via unspecified calls.

  - A boundary error in DAS server code can be exploited to cause a buffer
    overflow via via unspecified vectors.");
  script_tag(name:"solution", value:"Update DB2 8 Fixpak 17 or 9.1 Fixpak 5 or 9.5 Fixpak 2 or later.");
  script_tag(name:"summary", value:"The host is installed with IBM DB2 and is prone to multiple
  vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ibmVer = get_kb_item("Win/IBM-db2/Ver");
if(!ibmVer)
  exit(0);

# IBM DB2 9.1 FP4a =>9.1.401.444
# IBM DB2 9.5 FP1 =>9.5.100.179

if(version_in_range(version:ibmVer, test_version:"8.0",
                   test_version2:"8.1.16")||
   version_in_range(version:ibmVer, test_version:"9.1",
                   test_version2:"9.1.401.444")||
   version_in_range(version:ibmVer, test_version:"9.5",
                   test_version2:"9.5.100.179")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
