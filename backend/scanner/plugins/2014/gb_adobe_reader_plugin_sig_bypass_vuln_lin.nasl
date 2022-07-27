###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_plugin_sig_bypass_vuln_lin.nasl 11868 2018-10-12 10:53:07Z cfischer $
#
# Adobe Reader Plugin Signature Bypass Vulnerability (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.804626");
  script_version("$Revision: 11868 $");
  script_cve_id("CVE-2002-0030");
  script_bugtraq_id(7174);
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:53:07 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-06-04 17:27:52 +0530 (Wed, 04 Jun 2014)");
  script_name("Adobe Reader Plugin Signature Bypass Vulnerability (Linux)");


  script_tag(name:"summary", value:"This host is installed with Adobe Reader and is prone to plugin signature
bypass vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to fact the program only verifies the PE header of executable
code for a plug-in signature check.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to submit a modified plug-in to
bypass signature checks and execute malicious code on the system.");
  script_tag(name:"affected", value:"Adobe Reader 4.x and 5.x version on Linux.");
  script_tag(name:"solution", value:"Update to Adobe Reader version 6.0 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/11610");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/JSHA-5EZQGZ");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/vulnwatch/2003-q1/0148.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
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

if(readerVer =~ "^[4|5]\.")
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
