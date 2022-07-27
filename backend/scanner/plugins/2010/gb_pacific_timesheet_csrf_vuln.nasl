###############################################################################
# OpenVAS Vulnerability Test
#
# Pacific Timesheet Cross-Site Request Forgery Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800181");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-06-09 08:34:53 +0200 (Wed, 09 Jun 2010)");
  script_cve_id("CVE-2010-2111");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Pacific Timesheet Cross-Site Request Forgery Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39951");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58934");
  script_xref(name:"URL", value:"http://cross-site-scripting.blogspot.com/2010/05/pacific-timesheet-674-cross-site.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pacific_timesheet_detect.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_mandatory_keys("pacifictimesheet/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to perform unauthorized
  actions.");

  script_tag(name:"affected", value:"Pacific Timesheet version 6.74 build 363.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input.
  A remote attacker could exploit this vulnerability to perform cross-site
  request forgery by tricking a logged in administrator into visiting a
  malicious web site or link to perform unauthorized actions.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to version 6.75 or later.");

  script_tag(name:"summary", value:"This host is running Pacific Timesheet and is prone to cross-site
  request forgery vulnerability.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

pacificTSPort = get_http_port(default:80);

pacificTSVer = get_kb_item("www/" + pacificTSPort + "/pacificTimeSheet/Ver");
pacificTSVer = eregmatch(pattern:"^(.+) under (/.*)$", string:pacificTSVer);

if(pacificTSVer[1] != NULL)
{
  if(version_is_equal(version:pacificTSVer[1], test_version:"6.74.363")) {
    security_message(pacificTSPort);
  }
}
