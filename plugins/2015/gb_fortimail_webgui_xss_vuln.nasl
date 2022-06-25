###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fortimail_webgui_xss_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Fortinet FortiMail WebGUI Cross Site Scripting Vulnerability (FG-IR-15-005)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:fortinet:fortimail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805297");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2014-8617");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-03-04 15:19:22 +0530 (Wed, 04 Mar 2015)");
  script_name("Fortinet FortiMail WebGUI Cross Site Scripting Vulnerability (FG-IR-15-005)");

  script_tag(name:"summary", value:"This host is installed with Fortinet
  FortiMail and is prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because the 'Web Action
  Quarantine Release' feature does not validate input before returning it to
  users.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to create a specially crafted request that would execute
  arbitrary script code in a user's browser session within the trust relationship
  between their browser and the server.");

  script_tag(name:"affected", value:"FortiMail versions 4.3.x before 4.3.9,
  5.0.x before 5.0.8, 5.1.x before 5.1.5 and 5.2.x before 5.2.3");

  script_tag(name:"solution", value:"Upgrade to FortiMail version 4.3.9 or
  5.0.8 or 5.1.5 or 5.2.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"http://www.scip.ch/en/?vuldb.69250");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Mar/5");
  script_xref(name:"URL", value:"https://fortiguard.com/psirt/FG-IR-15-005");

  script_category(ACT_GATHER_INFO);
  script_family("FortiOS Local Security Checks");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_fortimail_version.nasl");
  script_mandatory_keys("fortimail/version");
  script_xref(name:"URL", value:"http://www.fortinet.com/products/fortimail");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

fortiVer = get_app_version(cpe:CPE);
if(!fortiVer){
  fortiVer = get_kb_item("fortiweb/version");
}

if(!fortiVer){
  exit( 0 );
}

if(version_in_range(version:fortiVer, test_version:"4.3.0", test_version2:"4.3.8"))
{
  fix = "4.3.9";
  VULN = TRUE ;
}

if(version_in_range(version:fortiVer, test_version:"5.0.0", test_version2:"5.0.7"))
{
  fix = "5.0.8";
  VULN = TRUE ;
}

if(version_in_range(version:fortiVer, test_version:"5.1.0", test_version2:"5.1.4"))
{
  fix = "5.1.5";
  VULN = TRUE ;
}

if(version_in_range(version:fortiVer, test_version:"5.2.0", test_version2:"5.2.2"))
{
  fix = "5.2.3";
  VULN = TRUE ;
}

if(VULN)
{
  model = get_kb_item("fortimail/model");
  if(!isnull(model))report = 'Model:             ' + model + '\n';
  report += 'Installed Version: ' + fortiVer + '\nFixed Version:     ' + fix + '\n';
  security_message(port:0, data:report);
  exit(0);
}

exit( 99 );
