###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Runtimes for Java Technology XML4J Unspecified Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800974");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-11-09 14:01:44 +0100 (Mon, 09 Nov 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3852");
  script_bugtraq_id(36894);
  script_name("IBM Runtimes for Java Technology XML4J Unspecified Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37210");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54069");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3106");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg1IZ63920");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("IBM/Java/JRE/Linux/Ver");
  script_tag(name:"impact", value:"Unknown impact.");
  script_tag(name:"affected", value:"IBM Runtimes for Java Technology 5.0.0 before SR10 on Linux.");
  script_tag(name:"insight", value:"An unspecified error occurs in the 'XML4J' component while parsing XML
  code.");
  script_tag(name:"summary", value:"This host is installed with IBM Runtime for Java Technology and
  is prone to unspecified vulnerability.");
  script_tag(name:"solution", value:"Apply the referenced vendor update.

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

jreVer = get_kb_item("IBM/Java/JRE/Linux/Ver");
if(!jreVer)
  exit(0);

if(version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.SR9")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
