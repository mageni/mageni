###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dokuwiki_mult_csrf_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# DokuWiki Multiple Cross Site Request Forgery Vulnerabilities
#
# Authors:
# Rachana Shetty <srachan@secpod.com>
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

CPE = "cpe:/a:dokuwiki:dokuwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800989");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-02-19 11:58:13 +0100 (Fri, 19 Feb 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0289");
  script_name("DokuWiki Multiple Cross Site Request Forgery Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dokuwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dokuwiki/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/38205");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0150");
  script_xref(name:"URL", value:"http://bugs.splitbrain.org/index.php?do=details&task_id=1853");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to conduct cross site request
  forgery attacks via unknown vectors.");
  script_tag(name:"affected", value:"Dokuwiki versions prior to 2009-12-25c");
  script_tag(name:"insight", value:"The flaws are due to error in 'ACL' Manager plugin (plugins/acl/ajax.php) that
  allows users to perform certain actions via HTTP requests without performing
  any validity checks.");
  script_tag(name:"solution", value:"Update to version 2009-12-25c or later.");
  script_tag(name:"summary", value:"This host is installed with Dokuwiki and is prone to multiple Cross
  Site Scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.splitbrain.org/go/dokuwiki");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"2009-12-25c" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2009-12-25c" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );