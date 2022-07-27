###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_edirectory_mult_vuln_feb15.nasl 11975 2018-10-19 06:54:12Z cfischer $
#
# Novell eDirectory iMonitor Multiple Vulnerabilities - Feb15
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805269");
  script_version("$Revision: 11975 $");
  script_cve_id("CVE-2014-5212", "CVE-2014-5213");
  script_bugtraq_id(71741, 71748);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:54:12 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-02-06 12:01:38 +0530 (Fri, 06 Feb 2015)");
  script_name("Novell eDirectory iMonitor Multiple Vulnerabilities - Feb15");
  script_tag(name:"summary", value:"This host is installed with Novell eDirectory
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple errors exists due to,

  - Improper sanitization by the /nds/search/data script when input is passed
    via the 'rdn' parameter.

  - An error in the /nds/files/opt/novell/eDirectory/lib64/ndsimon/public/images.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server, and disclose virtual memory
  including passwords.");

  script_tag(name:"affected", value:"Novell eDirectory versions prior to 8.8 SP8
  Patch 4");

  script_tag(name:"solution", value:"Upgrade to Novell eDirectory version 8.8 SP8
  Patch 4 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1031408");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/534284");
  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=3426981");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("novell_edirectory_detect.nasl");
  script_mandatory_keys("eDirectory/installed");
  script_require_ports("Services/ldap", 389, 636);
  script_xref(name:"URL", value:"https://www.netiq.com");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

CPE = make_list( "cpe:/a:novell:edirectory","cpe:/a:netiq:edirectory" );

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! major = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( ! sp = get_kb_item( "ldap/eDirectory/" + port + "/sp" ) )
  sp = "0";

instvers = major;

if( sp > 0 )
  instvers += ' SP' + sp;

revision = get_kb_item( "ldap/eDirectory/" + port + "/build" );
revision = str_replace( string:revision, find:".", replace:"" );

if( major <= "8.8" && sp <= "8" && revision <= "2080404" )
{
  report = 'Installed version: ' + instvers + '\n' +
           'Fixed version:     8.8 SP8 Patch4\n';
  security_message(data:report, port:port);
  exit(0);
}
