###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_pdf_doc_dos_vuln_lin.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Adobe Reader PDF Handling Denial Of Service Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801305");
  script_version("$Revision: 12653 $");
  script_bugtraq_id(39470);
  script_cve_id("CVE-2010-1241");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-04-07 16:20:50 +0200 (Wed, 07 Apr 2010)");
  script_name("Adobe Reader PDF Handling Denial Of Service Vulnerability (Linux)");


  script_tag(name:"summary", value:"This host is installed with Adobe Reader and is prone to Denial of Service
vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to an error in 'custom heap management system', allows the
attackers to execute arbitrary code via a crafted program that is specified in
a PDF document.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code or cause
a denial of service via a crafted PDF document.");
  script_tag(name:"affected", value:"Adobe Reader version 9.3.1 on Linux.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 9.3.2 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://blog.didierstevens.com/2010/03/29/escape-from-pdf/");
  script_xref(name:"URL", value:"http://www.blackhat.com/html/bh-eu-10/bh-eu-10-briefings.html#Li");
  script_xref(name:"URL", value:"http://lists.immunitysec.com/pipermail/dailydave/2010-April/006075.html");
  script_xref(name:"URL", value:"http://lists.immunitysec.com/pipermail/dailydave/2010-April/006077.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Reader/Linux/Version");
  script_xref(name:"URL", value:"http://www.adobe.com");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer =~ "^9")
{
  if(version_is_equal(version:readerVer, test_version:"9.3.1")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
