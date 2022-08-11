###############################################################################
# OpenVAS Vulnerability Test
#
# IBM DB2 UDB Multiple Unspecified Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By:
# Antu Sanadi <santu@secpod.com> on 2009/12/29 #6444
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
  script_oid("1.3.6.1.4.1.25623.1.0.901082");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-12-23 08:41:41 +0100 (Wed, 23 Dec 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4328", "CVE-2009-4329", "CVE-2009-4330", "CVE-2009-4333",
                "CVE-2009-4335", "CVE-2009-4439");
  script_bugtraq_id(37332);
  script_name("IBM DB2 UDB Multiple Unspecified Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37759");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3520");
  script_xref(name:"URL", value:"ftp://ftp.software.ibm.com/ps/products/db2/fixes/english-us/aparlist/db2_v95/APARLIST.TXT");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=0&uid=swg24022678");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Databases");
  script_dependencies("secpod_ibm_db2_detect_win_900218.nasl");
  script_mandatory_keys("Win/IBM-db2/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass security restrictions,
  cause a denial of service.");
  script_tag(name:"affected", value:"IBM DB2 version 9.5 prior to Fixpak 5");
  script_tag(name:"insight", value:"The flaws are due to:

  - An unspecified error in the Engine Utilities component, causes segmentation
    fault by modifying the db2ra data stream sent in a request from the load
    utility.

  - An unspecified error in 'db2licm' within the Engine Utilities component it
    has unknown impact and local attack vectors.

  - An unspecified error in the DRDA Services componenta, causes the server trap
    by calling a SQL stored procedure in unknown circumstances.

  - An error in relational data services component, allows attackers to obtain
    the password argument from the SET ENCRYPTION PASSWORD statement via vectors
    involving the GET SNAPSHOT FOR DYNAMIC SQL command.

  - Multiple unspecified errors in bundled stored procedures in the Spatial
    Extender component, have unknown impact and remote attack vectors.

  - An unspecified vulnerability in the Query Compiler, Rewrite, and Optimizer
    component, allows to cause a denial of service (instance crash) by compiling
    a SQL query.");
  script_tag(name:"solution", value:"Update IBM DB2 9.5 Fixpak 5.");
  script_tag(name:"summary", value:"The host is installed with IBM DB2 and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

ibmVer = get_kb_item("Win/IBM-db2/Ver");
if(!ibmVer)
  exit(0);

if(version_in_range(version:ibmVer, test_version:"9.5", test_version2:"9.5.500.783")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
