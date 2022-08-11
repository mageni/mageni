###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_squirrelmail_cmd_exec_vuln.nasl 14033 2019-03-07 11:09:35Z cfischer $
#
# SquirrelMail Command Execution Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

CPE = 'cpe:/a:squirrelmail:squirrelmail';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900713");
  script_version("$Revision: 14033 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 12:09:35 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-05-29 07:35:11 +0200 (Fri, 29 May 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1381");
  script_bugtraq_id(34916);
  script_name("SquirrelMail Command Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("squirrelmail_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("squirrelmail/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35140");
  script_xref(name:"URL", value:"http://www.debian.org/security/2009/dsa-1802");
  script_xref(name:"URL", value:"http://release.debian.org/proposed-updates/stable_diffs/squirrelmail_1.4.15-4+lenny2.debdiff");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary commands into
  the context of the affected web mailing application and can conduct cross site
  scripting, session fixation or phishing attacks.");

  script_tag(name:"affected", value:"SquirrelMail version prior to 1.4.19.");

  script_tag(name:"insight", value:"The flaw is due to improper handling of arbitrary commands in map_yp_alias
  function in functions/imap_general.php file via shell metacharacters in a
  username string that is used by the ypmatch program.");

  script_tag(name:"solution", value:"Upgrade to SquirrelMail version 1.4.19 or later.");

  script_tag(name:"summary", value:"This host is running SquirrelMail Web application and is prone
  to command execution vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"1.4.18" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.4.19" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );