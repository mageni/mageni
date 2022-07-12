###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_fms_prv_esc_vuln.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Adobe Flash Media Server Privilege Escalation Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:adobe:flash_media_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800560");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1365");
  script_bugtraq_id(34790);
  script_name("Adobe Flash Media Server Privilege Escalation Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_adobe_fms_detect.nasl");
  script_require_ports("Services/www", 1111);
  script_mandatory_keys("Adobe/FMS/installed");

  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb09-05.html");

  script_tag(name:"impact", value:"Successful attack could result in execution of crafted RPC Calls to the
  ActionScript file and cause injection of remote procedures into the context
  of the affected system.");

  script_tag(name:"affected", value:"Adobe Flash Media Server before 3.0.4, 3.5.x before 3.5.2 on all platforms.");

  script_tag(name:"insight", value:"This flaw is caused while executing RPC calls made to an ActionScript file
  running under Flash Media Server.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Media Server 3.5.2 or 3.0.4 or later.");

  script_tag(name:"summary", value:"This host has Adobe Flash Media Server installed and is prone to
  Privilege Escalation vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"3.5", test_version2:"3.5.1" ) ||
    version_is_less( version:vers, test_version:"3.0.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.4/3.5.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );