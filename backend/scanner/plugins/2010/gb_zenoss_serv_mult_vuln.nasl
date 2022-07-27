###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zenoss_serv_mult_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Zenoss Server Multiple Vulnerabilities
#
# Authors:
# Rachana Shetty <srachan@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:zenoss:zenoss";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800990");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0712", "CVE-2010-0713");
  script_bugtraq_id(37802, 37843);
  script_name("Zenoss Server Multiple Vulnerabilities");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_zenoss_serv_detect.nasl");
  script_mandatory_keys("ZenossServer/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/38195");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/55670");
  script_xref(name:"URL", value:"http://dev.zenoss.org/trac/changeset/15257");
  script_xref(name:"URL", value:"http://www.ngenuity.org/wordpress/2010/01/14/ngenuity-2010-002-zenoss-multiple-admin-csrf/");
  script_xref(name:"URL", value:"http://www.zenoss.com/news/SQL-Injection-and-Cross-Site-Forgery-in-Zenoss-Core-Corrected.html");
  script_xref(name:"URL", value:"http://www.ngenuity.org/wordpress/2010/01/14/ngenuity-2010-001-zenoss-getjsoneventsinfo-sql-injection/");
  script_xref(name:"URL", value:"http://www.zenoss.com/product/network-monitoring");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to view, add, modify or
  delete information in the back-end database or conduct cross site request
  forgery attacks.");

  script_tag(name:"affected", value:"Zenoss Server versions prior to 2.5.");

  script_tag(name:"insight", value:"- Input passed via the 'severity', 'state', 'filter', 'offset', and 'count'
    parameters to /zport/dmd/Events/getJSONEventsInfo is not properly
    sanitised before being used in SQL queries.

  - The application allows administrative users to perform certain actions via
    HTTP requests without performing any validity checks to verify the
    requests. This can be exploited to e.g. change administrator passwords via
    zport/dmd/ZenUsers/admin or execute arbitrary shell commands via
    zport/dmd/userCommands/ by tricking an administrative user into visiting
    a malicious web site.");

  script_tag(name:"solution", value:"Update to version 2.5 or later. Please see the
  references for more info.");

  script_tag(name:"summary", value:"The host is running Zenoss Server and is prone to multiple
  vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"2.5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.5" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );