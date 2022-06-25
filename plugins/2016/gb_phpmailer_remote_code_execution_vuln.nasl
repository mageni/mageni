###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmailer_remote_code_execution_vuln.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# PHPMailer < 5.2.18 Remote Code Execution Vulnerability.
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:phpmailer_project:phpmailer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809842");
  script_version("$Revision: 12051 $");
  script_cve_id("CVE-2016-10033");
  script_bugtraq_id(95108);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-27 16:29:41 +0530 (Tue, 27 Dec 2016)");
  script_name("PHPMailer < 5.2.18 Remote Code Execution Vulnerability.");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_phpmailer_detect.nasl");
  script_mandatory_keys("phpmailer/detected");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40968");
  script_xref(name:"URL", value:"http://thehackernews.com/2016/12/phpmailer-security.html?m=1");
  script_xref(name:"URL", value:"https://legalhackers.com/videos/PHPMailer-Exploit-Remote-Code-Exec-Vuln-CVE-2016-10033-PoC.html");
  script_xref(name:"URL", value:"https://github.com/PHPMailer/PHPMailer/blob/master/SECURITY.md");

  script_tag(name:"summary", value:"This host is running PHPMailer and is prone
  to remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to, PHPMailer uses the
  Sender variable to build the params string, The validation is done using the
  RFC 3696 specification, which can allow emails to contain spaces when it has
  double quote.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows an
  remote attacker to execute arbitrary code in the context of the web server and
  compromise the target web application.");

  script_tag(name:"affected", value:"PHPMailer versions prior to 5.2.18");

  script_tag(name:"solution", value:"Upgrade to PHPMailer 5.2.18 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );
version  = infos['version'];
location = infos['location'];

if( version_is_less( version:version, test_version:"5.2.18" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.2.18", install_url:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );