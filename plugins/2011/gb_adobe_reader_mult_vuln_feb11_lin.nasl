###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_mult_vuln_feb11_lin.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Adobe Reader Multiple Vulnerabilities February-2011 (Linux)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801845");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2010-4091", "CVE-2011-0562", "CVE-2011-0563",
                "CVE-2011-0564", "CVE-2011-0565", "CVE-2011-0566",
                "CVE-2011-0567", "CVE-2011-0568", "CVE-2011-0570",
                "CVE-2011-0585", "CVE-2011-0586", "CVE-2011-0587",
                "CVE-2011-0588", "CVE-2011-0589", "CVE-2011-0590",
                "CVE-2011-0591", "CVE-2011-0592", "CVE-2011-0593",
                "CVE-2011-0594", "CVE-2011-0595", "CVE-2011-0596",
                "CVE-2011-0598", "CVE-2011-0599", "CVE-2011-0600",
                "CVE-2011-0602", "CVE-2011-0603", "CVE-2011-0604",
                "CVE-2011-0605", "CVE-2011-0606");
  script_bugtraq_id(46146);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-02-15 08:14:35 +0100 (Tue, 15 Feb 2011)");
  script_name("Adobe Reader Multiple Vulnerabilities February-2011 (Linux)");


  script_tag(name:"summary", value:"This host is installed with Adobe Reader and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are present in Adobe Reader due to insecure permissions, input
validation errors, memory corruptions, and buffer overflow errors when
processing malformed contents within a PDF document.");
  script_tag(name:"impact", value:"Successful exploitation will let local attackers to obtain elevated
privileges, or by remote attackers to inject scripting code, or execute
arbitrary commands by tricking a user into opening a malicious PDF document.");
  script_tag(name:"affected", value:"Adobe Reader 9.4.1 and earlier versions for Linux.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 9.4.2 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0337");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-03.html");
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

if(version_is_less(version:readerVer, test_version:"9.4.2"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
