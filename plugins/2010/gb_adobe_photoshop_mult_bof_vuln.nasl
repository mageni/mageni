###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_photoshop_mult_bof_vuln.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Adobe Photoshop Multiple Buffer Overflow Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:photoshop_cs4";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801221");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-06-15 06:05:27 +0200 (Tue, 15 Jun 2010)");
  script_bugtraq_id(40389);
  script_cve_id("CVE-2010-1296");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Photoshop Multiple Buffer Overflow Vulnerabilities");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58888");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-13.html");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4940.php");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4939.php");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4938.php");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_adobe_photoshop_detect.nasl");
  script_mandatory_keys("Adobe/Photoshop/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code within the context of the affected application or cause denial of service.");
  script_tag(name:"affected", value:"Adobe Photoshop CS4 before 11.0.2");
  script_tag(name:"insight", value:"This flaw is caused by improper bounds checking on user-supplied data,
  which could allow a remote attacker to execute arbitrary code on the system
  by persuading a victim to open a specially-crafted 'ASL', '.ABR', or '.GRD' file.");
  script_tag(name:"solution", value:"Upgrade to Adobe Photoshop CS4 11.0.2 or later.");
  script_tag(name:"summary", value:"This host is installed with Adobe Photoshop and is prone to Buffer
  Overflow vulnerability.");

  script_xref(name:"URL", value:"http://www.adobe.com/downloads/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if( version_is_less( version:vers, test_version:"11.0.2" ) ) {
  report = report_fixed_ver( installed_version:"CS4 " + vers, fixed_version:"11.0.2", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
