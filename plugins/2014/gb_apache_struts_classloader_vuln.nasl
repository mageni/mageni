###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_classloader_vuln.nasl 13884 2019-02-26 13:35:59Z cfischer $
#
# Apache Struts ClassLoader Manipulation Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105910");
  script_name("Apache Struts ClassLoader Manipulation Vulnerabilities");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 13884 $");
  script_bugtraq_id(65999, 67064);
  script_cve_id("CVE-2014-0094", "CVE-2014-0112");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 14:35:59 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-05-14 13:53:39 +0700 (Wed, 14 May 2014)");
  script_category(ACT_MIXED_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_apache_struts2_detection.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 8080, 80);
  script_mandatory_keys("ApacheStruts/installed");

  script_xref(name:"URL", value:"http://struts.apache.org/release/2.3.x/docs/s2-020.html");
  script_xref(name:"URL", value:"http://struts.apache.org/release/2.3.x/docs/s2-021.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65999");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67064");

  script_tag(name:"summary", value:"ClassLoader Manipulation allows remote attackers to to execute
  arbitrary Java code");

  script_tag(name:"vuldetect", value:"Check installed version or check the found apps.");

  script_tag(name:"solution", value:"Upgrade Apache Struts to 2.3.16.2 or higher.");

  script_tag(name:"insight", value:"The ParametersInterceptor allows remote attackers to manipulate
  the ClassLoader via the class parameter, which is passed to the getClass method.");

  script_tag(name:"affected", value:"Apache Struts 2.0.0 to 2.3.16.1");

  script_tag(name:"impact", value:"A remote attacker can execute arbitrary Java code via crafted
  parameters");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");

if (port = get_app_port(cpe:CPE)) {
  strutsVer = "";
  if (strutsVer = get_app_version(cpe:CPE, port:port)) {
    if (version_in_range(version:strutsVer, test_version:"2.0.0", test_version2:"2.3.16.1")) {
      report = report_fixed_ver( installed_version:strutsVer, fixed_version: "2.3.16.2" );
      security_message(port:port, data:report);
      exit(0);
    } else {
      exit(99);
    }
  }
}

port = get_http_port(default:80);
host = http_host_name(dont_add_port:TRUE);

# See if we have some apps deployed to check
if(!apps = http_get_kb_cgis(port:port, host:host)) exit(0);

foreach app (apps) {
  if (".action" >< app) {
    end = strstr(app, " ");
    dir = app - end;
    url = dir + '?Class.classLoader.resources.dirContext.cacheObjectMaxSize=x';
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    if ("No result defined for action" >< res) {
      report = report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);