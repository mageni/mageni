###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_db2_mult_dos_vuln_lin02.nasl 12670 2018-12-05 14:14:20Z cfischer $
#
# IBM DB2 Multiple Vulnerabilities (Linux)
#
# Authors:
# Antu Sanadi<santu@secpod.com>
#
# Updated KB Name
# Antu Sanadi <santu@secpod.com> on 2009-12-21
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
  script_oid("1.3.6.1.4.1.25623.1.0.900679");
  script_version("$Revision: 12670 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 15:14:20 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-6821", "CVE-2008-6820", "CVE-2008-2154");
  script_bugtraq_id(31058, 35409);
  script_name("IBM DB2 Multiple Vulnerabilities (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/31787");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Jun/1022319.htm");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1JR30227");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=0&uid=swg24022678");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Databases");
  script_dependencies("secpod_ibm_db2_detect_linux_900217.nasl");
  script_mandatory_keys("Linux/IBM_db2/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass security restrictions,
  cause a denial of service or gain elevated privileges.");

  script_tag(name:"affected", value:"IBM DB2 version 8 prior to Fixpak 17

  IBM DB2 version 9.1 prior to Fixpak 5

  IBM DB2 version 9.5 prior to Fixpak 2");

  script_tag(name:"insight", value:"The flaws are due to,

  - An unspecified error related to the DB2FMP process running
  with OS prvileges.

  - An error in INSTALL_JAR procedure might allow remote authenticated
  users to create or overwrite arbitrary files via unspecified calls.

  - A boundary error in DAS server code can be exploited to cause a buffer
  overflow via unspecified vectors.");

  script_tag(name:"solution", value:"Update DB2 8 Fixpak 17 or 9.1 Fixpak 5 or 9.5 Fixpak 2 or later.");

  script_tag(name:"summary", value:"The host is installed with IBM DB2 and is prone to multiple
  vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ibmVer = get_kb_item("Linux/IBM_db2/Ver");
if(!ibmVer){
  exit(0);
}

# IBM DB2 9.1 FP4a =>9.1.0.4
# IBM DB2 9.5 FP1 =>9.5.0.1

if(version_in_range(version:ibmVer, test_version:"8.0", test_version2:"8.1.16") ||
   version_in_range(version:ibmVer, test_version:"9.1", test_version2:"9.1.0.4") ||
   version_in_range(version:ibmVer, test_version:"9.5", test_version2:"9.5.0.1")){
  security_message(port:0);
}
