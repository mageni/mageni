##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_limny_mult_csrf_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Limny Multiple Cross-site Request Forgery (CSRF) Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

CPE = "cpe:/a:limny:limny";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800296");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-03-02 12:02:59 +0100 (Tue, 02 Mar 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0709");
  script_name("Limny Multiple Cross-site Request Forgery (CSRF) Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_limny_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("limny/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/38616");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56318");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/11478");

  script_tag(name:"insight", value:"The multiple flaws are caused by improper validation of user-supplied input,
  which allows users to perform certain actions via HTTP requests without
  performing any validity checks to verify the requests.");
  script_tag(name:"solution", value:"Upgrade to Limny version 2.01");
  script_tag(name:"summary", value:"This host is running Limny is prone to multiple cross-site request
  forgery vulnerabilities");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to change the administrative
  password or email address and add a new user by tricking an administrative user
  into visiting a malicious web site.");
  script_tag(name:"affected", value:"Limny version 2.0");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.limny.org/");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less_equal( version:vers, test_version:"2.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.01" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );