###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_virtualbox_mult_mem_corr_vuln_macosx.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Oracle VM VirtualBox Multiple Memory Corruption Vulnerabilities (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804357");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-0981", "CVE-2014-0983");
  script_bugtraq_id(66131, 66133);
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-04-02 18:30:36 +0530 (Wed, 02 Apr 2014)");
  script_name("Oracle VM VirtualBox Multiple Memory Corruption Vulnerabilities (Mac OS X)");


  script_tag(name:"summary", value:"This host is installed with Oracle VM VirtualBox and is prone to multiple
memory corruption vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An error within the 'crNetRecvReadback' function.

  - Multiple errors within the 'crNetRecvReadback' and 'crNetRecvWriteback'
  functions.

  - A boundary error within multiple generated 'crServerDispatchVertexAttrib*ARB'
  functions.");
  script_tag(name:"impact", value:"Successful exploitation will allow local users to conduct a denial of service
or potentially execute arbitrary code.");
  script_tag(name:"affected", value:"Oracle VM VirtualBox version 4.2.x through 4.2.20, 4.3.x before 4.3.8 on
Mac OS X.");
  script_tag(name:"solution", value:"Upgrade to Oracle VM VirtualBox version 4.3.8 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57384");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/32208");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125660");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_oracle_virtualbox_detect_macosx.nasl");
  script_mandatory_keys("Oracle/VirtualBox/MacOSX/Version");
  script_xref(name:"URL", value:"https://www.virtualbox.org");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!virtualVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(virtualVer =~ "^(4\.(2|3))")
{
  if(version_in_range(version:virtualVer, test_version:"4.2.0", test_version2:"4.2.20")||
     version_in_range(version:virtualVer, test_version:"4.3.0", test_version2:"4.3.7"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
