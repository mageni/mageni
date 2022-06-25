###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_privelege_escalation_vuln_oct09_macosx.nasl 11974 2018-10-19 06:22:46Z cfischer $
#
# Adobe Reader 'Download Manager' Privilege Escalation Vulnerability (Mac OS X)
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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804369");
  script_version("$Revision: 11974 $");
  script_cve_id("CVE-2009-2564");
  script_bugtraq_id(35740);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:22:46 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-04-08 16:36:34 +0530 (Tue, 08 Apr 2014)");
  script_name("Adobe Reader 'Download Manager' Privilege Escalation Vulnerability (Mac OS X)");


  script_tag(name:"summary", value:"This host is installed with Adobe Reader and is prone to privilege escalation
vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to insecure permissions being set on the NOS installation
directory within Corel getPlus Download Manager.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain escalated privileges on
the system.");
  script_tag(name:"affected", value:"Adobe Reader 7.x before 7.1.4, 8.x before 8.1.7 and 9.x before 9.2 on
Mac OS X.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader 7.1.4 or 8.1.7 or 9.2 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35930");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1023007");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/9199");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54383");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb09-15.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Reader/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.adobe.com/downloads");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer && readerVer =~ "^(9|8|7)")
{
  if(version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.1.3")||
     version_in_range(version:readerVer, test_version:"8.0", test_version2:"8.1.6")||
     version_in_range(version:readerVer, test_version:"7.0", test_version2:"7.1.3"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
