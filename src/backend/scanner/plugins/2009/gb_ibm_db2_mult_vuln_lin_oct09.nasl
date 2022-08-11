###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_db2_mult_vuln_lin_oct09.nasl 12670 2018-12-05 14:14:20Z cfischer $
#
# IBM DB2 Multiple Vulnerabilities - Oct09 (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801001");
  script_version("$Revision: 12670 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 15:14:20 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-10-06 07:21:15 +0200 (Tue, 06 Oct 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3471", "CVE-2009-3472");
  script_bugtraq_id(36540);
  script_name("IBM DB2 Multiple Vulnerabilities - Oct09 (Linux)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36890");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21403619");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21386689");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg27007053");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("secpod_ibm_db2_detect_linux_900217.nasl");
  script_mandatory_keys("Linux/IBM_db2/Ver");

  script_tag(name:"impact", value:"Unknown impact.");

  script_tag(name:"affected", value:"IBM DB2 version 8 prior to Fixpak 18

  IBM DB2 version 9.1 prior to Fixpak 8

  IBM DB2 version 9.5 prior to Fixpak 4");

  script_tag(name:"insight", value:"- An unspecified error exists related to a table function when the definer
  loses required privileges.

  - An unspecified error can be exploited to insert, update, or delete rows in
  a table without having required privileges.");

  script_tag(name:"solution", value:"Update DB2 8 Fixpak 18 or 9.1 Fixpak 8 or 9.5 Fixpak 4 or later.");

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

# 9.1 FP8 =>9.1.0.8, 9.5 FP4 =>9.5.0.4, 8 FP18 =>8.1.18
if(version_in_range(version:ibmVer, test_version:"8.0", test_version2:"8.1.17")||
   version_in_range(version:ibmVer, test_version:"9.1", test_version2:"9.1.0.7")||
   version_in_range(version:ibmVer, test_version:"9.5", test_version2:"9.5.0.3")){
  security_message(port:0);
}
