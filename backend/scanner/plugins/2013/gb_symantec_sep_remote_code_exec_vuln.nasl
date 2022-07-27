###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_sep_remote_code_exec_vuln.nasl 11883 2018-10-12 13:31:09Z cfischer $
#
# Symantec Endpoint Protection Management Console Remote Code Execution Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803094");
  script_version("$Revision: 11883 $");
  script_cve_id("CVE-2012-4348");
  script_bugtraq_id(56846);
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:31:09 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-01-08 10:42:29 +0530 (Tue, 08 Jan 2013)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:M/C:C/I:C/A:C");
  script_name("Symantec Endpoint Protection Management Console Remote Code Execution Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51527");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/80601");
  script_xref(name:"URL", value:"http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20121210_00");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec_or_Norton/Products/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow remote authenticated users to execute
  arbitrary code via unspecified vectors.");
  script_tag(name:"affected", value:"Symantec Endpoint Protection (SEP) versions 11.0 before RU7-MP3 and 12.1 before RU2
  Symantec Endpoint Protection Small Business Edition version 12.x before 12.1 RU2");
  script_tag(name:"insight", value:"The decomposer engine in Symantec Products fails to properly validate input
  for PHP scripts.");
  script_tag(name:"solution", value:"Upgrade to Symantec Endpoint Protection (SEP) version 11.0 RU7-MP3 or SEP12.1 RU2 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with Symantec Endpoint Protection and is
  prone to remote code execution vulnerability.");
  exit(0);
}


include("version_func.inc");

sepVer = get_kb_item("Symantec/Endpoint/Protection");
if(!sepVer){
 exit(0);
}

sepType = get_kb_item("Symantec/SEP/SmallBusiness");

## 11.x before RU7-MP3 (11.0.7300.1294) and 12.1 before RU2 (12.1.2015.2015)
if(isnull(sepType) &&
   version_in_range(version:sepVer, test_version:"11.0", test_version2:"11.0.7300.1293")||
   version_in_range(version:sepVer, test_version:"12.1", test_version2:"12.1.2015.2014"))
{
   security_message( port: 0, data: "The target host was found to be vulnerable" );
   exit(0);
}

if("sepsb" >< sepType  && sepVer =~ "^12" &&
   version_is_less(version:sepVer, test_version:"12.1.2015.2015"))
{
   security_message( port: 0, data: "The target host was found to be vulnerable" );
   exit(0);
}
