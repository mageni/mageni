###############################################################################
# OpenVAS Vulnerability Test
#
# FrontAccounting Multiple SQL Injection Vulnerabilities
#
# Authors:
# Maneesh KB <kmaneesh@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900257");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2009-11-30 15:32:46 +0100 (Mon, 30 Nov 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4037", "CVE-2009-4045");
  script_name("FrontAccounting Multiple SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37327");
  script_xref(name:"URL", value:"http://frontaccounting.net/wb3/pages/posts/2.1.7-security-release103.php");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_frontaccounting_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("frontaccounting/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to access and modify the backend
  database by conducting SQL injection attacks.");

  script_tag(name:"affected", value:"FrontAccounting versions prior to 2.1.7.");

  script_tag(name:"insight", value:"Input passed via multiple unspecified parameters to various scripts is not
  properly sanitised before being used in SQL queries. This can be exploited
  to manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to FrontAccounting version 2.1.7.");

  script_tag(name:"summary", value:"This host is running FrontAccounting and is prone to multiple SQL Injection
  vulnerabilities.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

faPort = get_http_port(default:80);

faVer = get_kb_item("www/" + faPort + "/FrontAccounting");
if(!faVer)
  exit(0);

faVer = eregmatch(pattern:"^(.+) under (/.*)$", string:faVer);
if(faVer[1])
{
  if(version_is_less(version:faVer[1], test_version:"2.1.7")){
    security_message(port:faPort, data:"The target host was found to be vulnerable.");
    exit(0);
  }
}

exit(99);
