###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_int_overflow_vuln_lin_jan12.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Adobe Reader Integer Overflow Vulnerability - Jan 12 (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802421");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2011-4374");
  script_bugtraq_id(51557);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-01-23 15:55:01 +0530 (Mon, 23 Jan 2012)");
  script_name("Adobe Reader Integer Overflow Vulnerability - Jan 12 (Linux)");


  script_tag(name:"summary", value:"This host is installed with Adobe Reader and is prone to integer overflow
vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to an integer overflow error, which allow the attackers to
execute arbitrary code via unspecified vectors.");
  script_tag(name:"impact", value:"Successful exploitation will allow the attackers to execute arbitrary code
via unspecified vectors.");
  script_tag(name:"affected", value:"Adobe Reader version 9.x before 9.4.6 on Linux.");
  script_tag(name:"solution", value:"Upgrade Adobe Reader to 9.4.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-24.html");
  script_xref(name:"URL", value:"http://people.canonical.com/~ubuntu-security/cve/2011/CVE-2011-4374.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
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
  if(version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.4.5")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
