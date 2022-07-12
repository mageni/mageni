###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmailer_sendmailsend_cmd_rce.nasl 14156 2019-03-13 14:38:13Z cfischer $
#
# PHPMailer < 2.0.0 rc1 'SendmailSend' Remote Code Execution Vulnerability
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108471");
  script_version("$Revision: 14156 $");
  script_cve_id("CVE-2007-3215");
  script_bugtraq_id(24417);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 15:38:13 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-09-25 09:59:32 +0200 (Tue, 25 Sep 2018)");
  script_name("PHPMailer < 2.0.0 rc1 'SendmailSend' Remote Code Execution Vulnerability");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_phpmailer_detect.nasl");
  script_mandatory_keys("phpmailer/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/24417");
  script_xref(name:"URL", value:"https://github.com/PHPMailer/PHPMailer/blob/master/changelog.md#version-200-rc1-thu-nov-08-2007-interim-release");
  script_xref(name:"URL", value:"https://github.com/PHPMailer/PHPMailer/blob/master/SECURITY.md");

  script_tag(name:"summary", value:"This host is running PHPMailer and is prone
  to a remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"PHPMailer, when configured to use sendmail, allows remote attackers to execute arbitrary
  shell commands via shell metacharacters in the SendmailSend function in class.phpmailer.php.");

  script_tag(name:"affected", value:"PHPMailer versions 1.7 and earlier are vulnerable.");

  script_tag(name:"solution", value:"Upgrade to PHPMailer 2.0.0 rc1 or later.");

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

# nb: Advisory says "1.7 and earlier" but changelog shows that its fixed in 2.0.0 rc1.
if( version_is_less( version:version, test_version:"2.0.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.0.0 rc1", install_url:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );