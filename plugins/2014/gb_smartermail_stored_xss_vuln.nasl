###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_smartermail_stored_xss_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# SmarterMail Enterprise and Standard Stored XSS vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:smartertools:smartermail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803793");
  script_version("$Revision: 11402 $");
  script_bugtraq_id(64970);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-01-20 13:17:30 +0530 (Mon, 20 Jan 2014)");
  script_name("SmarterMail Enterprise and Standard Stored XSS vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_smartermail_detect.nasl");
  script_require_ports("Services/www", 80, 9998);
  script_mandatory_keys("SmarterMail/installed");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/31017");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2014010100");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124792/smartermail11-xss.txt");

  script_tag(name:"summary", value:"This host is running SmarterMail Enterprise/Standard and is prone to stored
  cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw due to an improper validation, input passed via the email body before
  returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML or
  script code.");

  script_tag(name:"affected", value:"SmarterMail Enterprise and Standard versions 11.x and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less_equal( version:vers, test_version:"11.7" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"No fix available" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );