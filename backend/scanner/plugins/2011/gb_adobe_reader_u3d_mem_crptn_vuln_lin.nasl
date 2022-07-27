###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_u3d_mem_crptn_vuln_lin.nasl 12014 2018-10-22 10:01:47Z mmartin $
#
# Adobe Reader 'U3D' Component Memory Corruption Vulnerability - Linux
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802544");
  script_version("$Revision: 12014 $");
  script_cve_id("CVE-2011-2462", "CVE-2011-4369");
  script_bugtraq_id(50922, 51092);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 12:01:47 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-09 12:52:04 +0530 (Fri, 09 Dec 2011)");
  script_name("Adobe Reader 'U3D' Component Memory Corruption Vulnerability - Linux");


  script_tag(name:"summary", value:"This host is installed with Adobe Reader and is prone to memory corruption
vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to an unspecified error while handling U3D data.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code in the
context of the affected application or cause a denial of service.");
  script_tag(name:"affected", value:"Adobe Reader versions 9.x through 9.4.6 on Linux");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 9.4.7 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47133/");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa11-04.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Reader/Linux/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer =~ "^9")
{
  if(version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.4.6"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
