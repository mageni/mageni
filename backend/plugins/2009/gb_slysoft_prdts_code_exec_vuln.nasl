###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_slysoft_prdts_code_exec_vuln.nasl 14325 2019-03-19 13:35:02Z asteins $
#
# SlySoft Product(s) Code Execution Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.800392");
  script_version("$Revision: 14325 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:35:02 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-04-16 16:39:16 +0200 (Thu, 16 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-0824");
  script_bugtraq_id(34103);
  script_name("SlySoft Product(s) Code Execution Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34269");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34289");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34287");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34288");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/501713/100/0/threaded");
  script_xref(name:"URL", value:"http://www.slysoft.com/en/download.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_slysoft_prdts_detect.nasl");
  script_mandatory_keys("Slysoft/Products/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause memory corruption and
  can allow remote code execution in the context of the affected system,
  which result in service crash.");
  script_tag(name:"affected", value:"SlySoft AnyDVD version prior to 6.5.2.6.

  SlySoft CloneCD version 5.3.1.3 and prior.

  SlySoft CloneDVD version 2.9.2.0 and prior.

  SlySoft Virtual CloneDrive version 5.4.2.3 and prior.");
  script_tag(name:"insight", value:"METHOD_NEITHER communication method for IOCTLs does not properly validate
  a buffer associated with the Irp object of user space data provided to
  the ElbyCDIO.sys kernel driver.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to higher versions accordingly.");
  script_tag(name:"summary", value:"This host is installed with SlySoft Products and is prone
  to a Code Execution Vulnerability.");
  exit(0);
}


include("version_func.inc");

anydvdVer = get_kb_item("AnyDVD/Ver");
if(anydvdVer)
{
  if(version_is_less(version:anydvdVer, test_version:"6.5.2.6"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

clonecdVer = get_kb_item("CloneCD/Ver");
if(clonecdVer)
{
  if(version_is_less_equal(version:clonecdVer, test_version:"5.3.1.3"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

clonedvdVer = get_kb_item("CloneDVD/Ver");
if(clonedvdVer)
{
  if(version_is_less_equal(version:clonedvdVer, test_version:"2.9.2.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vcdVer = get_kb_item("VirtualCloneDrive/Ver");
if(vcdVer)
{
  if(version_is_less_equal(version:vcdVer, test_version:"5.4.2.3")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

exit(99);
