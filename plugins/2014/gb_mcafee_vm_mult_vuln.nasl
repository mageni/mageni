###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_vm_mult_vuln.nasl 2014-03-20 14:52:54Z mar$
#
# McAfee Vulnerability Manager Multiple Vulnerabilities
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
CPE = "cpe:/a:mcafee:vulnerability_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804250");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-1472", "CVE-2014-1473", "CVE-2013-5094");
  script_bugtraq_id(64795, 58401);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-03-20 14:52:54 +0530 (Thu, 20 Mar 2014)");
  script_name("McAfee Vulnerability Manager Multiple Vulnerabilities");


  script_tag(name:"summary", value:"This host is installed with McAfee Vulnerability Manager and is prone to
multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Improper validation of user supplied input passed to 'cert_cn' parameter.

  - Other multiple flaws are caused by improper validation of user-supplied
  input.");
  script_tag(name:"impact", value:"Successful exploitation will allow a local attacker to steal the victim's
cookie-based authentication credentials.");
  script_tag(name:"affected", value:"McAfee Vulnerability Manager 7.5.5 and earlier.");
  script_tag(name:"solution", value:"Vendor has released a patch to fix this issue, please the the references for more info.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/56394");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/90244");
  script_xref(name:"URL", value:"http://asheesh2000.blogspot.in/2013/08/mcafee-vulnerability-manager-75-cross.html");
  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10061");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mcafee_vulnerability_manager_detect.nasl");
  script_mandatory_keys("McAfee/Vulnerability/Manager");
  script_xref(name:"URL", value:"http://www.mcafee.com/in/products/vulnerability-manager.aspx");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!mVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:mVer, test_version:"7.5.5", test_version2:"7.5.5.05001") ||
   version_in_range(version:mVer, test_version:"7.5.4", test_version2:"7.5.4.05006") ||
   version_in_range(version:mVer, test_version:"7.0.11", test_version2:"7.0.11.05001"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
