###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_web_analytics_sql_inj_vuln.nasl 34614 2014-01-03 11:00:19Z Jan$
#
# Open Web Analytics < 1.5.7 PHP Object Injection Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.112261");
  script_version("$Revision: 9758 $");
  script_cve_id("CVE-2014-2294");
  script_bugtraq_id(66076);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-05-08 14:29:26 +0200 (Tue, 08 May 2018) $");
  script_tag(name:"creation_date", value:"2018-04-26 13:50:11 +0200 (Thu, 26 Apr 2018)");

  script_name("Open Web Analytics < 1.5.7 PHP Object Injection Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Open Web Analytics and is prone to a PHP object injection vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Open Web Analytics (OWA) before 1.5.7 allows remote attackers to conduct PHP object injection attacks via a crafted serialized object in the owa_event parameter to queue.php.");
  script_tag(name:"impact", value:"This issue could be exploited to change certain configuration options or create a file containing arbitrary PHP code via specially crafted serialized objects.");
  script_tag(name:"affected", value:"Open Web Analytics before version 1.5.7.");
  script_tag(name:"solution", value:"Update to version 1.5.7 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.openwebanalytics.com/?p=388");
  script_xref(name:"URL", value:"http://karmainsecurity.com/KIS-2014-03");
  script_xref(name:"URL", value:"https://secuniaresearch.flexerasoftware.com/advisories/56999");
  script_xref(name:"URL", value:"https://secuniaresearch.flexerasoftware.com/secunia_research/2014-3/");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_open_web_analytics_detect.nasl");
  script_mandatory_keys("OpenWebAnalytics/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:openwebanalytics:open_web_analytics";

if (!port = get_app_port(cpe:CPE)) exit(0);
if (!version = get_app_version(cpe:CPE, port:port)) exit(0);

if (version_is_less(version:version, test_version:"1.5.7")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.5.7");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
