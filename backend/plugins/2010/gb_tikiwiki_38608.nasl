###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tikiwiki_38608.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Tiki Wiki CMS Groupware < 4.2 Multiple Unspecified Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100537");
  script_version("$Revision: 13960 $");
  script_bugtraq_id(38608);
  script_cve_id("CVE-2010-1135", "CVE-2010-1134", "CVE-2010-1133", "CVE-2010-1136");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-03-15 19:33:39 +0100 (Mon, 15 Mar 2010)");
  script_name("Tiki Wiki CMS Groupware < 4.2 Multiple Unspecified Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("secpod_tikiwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TikiWiki/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38608");
  script_xref(name:"URL", value:"http://tikiwiki.svn.sourceforge.net/viewvc/tikiwiki?view=rev&revision=24734");
  script_xref(name:"URL", value:"http://tikiwiki.svn.sourceforge.net/viewvc/tikiwiki?view=rev&revision=25046");
  script_xref(name:"URL", value:"http://tikiwiki.svn.sourceforge.net/viewvc/tikiwiki?view=rev&revision=25424");
  script_xref(name:"URL", value:"http://tikiwiki.svn.sourceforge.net/viewvc/tikiwiki?view=rev&revision=25435");
  script_xref(name:"URL", value:"http://info.tikiwiki.org/article86-Tiki-Announces-3-5-and-4-2-Releases");
  script_xref(name:"URL", value:"http://info.tikiwiki.org/tiki-index.php?page=homepage");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to compromise the
  application, access or modify data, exploit latent vulnerabilities in
  the underlying database, and gain unauthorized access to the affected
  application. Other attacks are also possible.");
  script_tag(name:"affected", value:"Versions prior to Tiki Wiki CMS Groupware 4.2 are vulnerable.");
  script_tag(name:"solution", value:"The vendor has released an advisory and fixes. Please see the
  references for details.");
  script_tag(name:"summary", value:"Tiki Wiki CMS Groupware is prone to multiple unspecified vulnerabilities, including:

  - An unspecified SQL-injection vulnerability

  - An unspecified authentication-bypass vulnerability

  - An unspecified vulnerability");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"4.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
