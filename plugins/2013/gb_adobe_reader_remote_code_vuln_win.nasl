##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_remote_code_vuln_win.nasl 32539 2013-10-18 08:30:08Z oct$
#
# Adobe Reader Remote Code Execution Vulnerability(Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804111");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-5325");
  script_bugtraq_id(62888);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-10-18 08:47:35 +0530 (Fri, 18 Oct 2013)");
  script_name("Adobe Reader Remote Code Execution Vulnerability(Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Reader and is prone to Remote Code
Execution Vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to Adobe Reader version 11.0.05 or later.");
  script_tag(name:"insight", value:"The flaw is due to some error affecting javascript security controls.");
  script_tag(name:"affected", value:"Adobe Reader version 11.x before 11.0.05 on Windows");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass the security controls
and execute arbitrary javascript code by launching javascript scheme URIs
when a PDF file is being viewed in a browser.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54754");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62888");
  script_xref(name:"URL", value:"https://www.adobe.com/support/security/bulletins/apsb13-25.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Installed");
  script_xref(name:"URL", value:"http://www.adobe.com/downloads/updates.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer =~ "^11\.0")
{
  if(version_in_range(version:readerVer, test_version:"11.0.0", test_version2:"11.0.04"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
