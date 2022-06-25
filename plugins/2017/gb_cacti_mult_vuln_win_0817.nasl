###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cacti_mult_vuln_win_0817.nasl 12131 2018-10-26 14:03:52Z mmartin $
#
# Cacti <= 0.8.8b Multiple Vulnerabilities (Windows)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:cacti:cacti";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108208");
  script_version("$Revision: 12131 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 16:03:52 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-16 11:05:37 +0200 (Wed, 16 Aug 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2013-1434", "CVE-2013-1435", "CVE-2013-5588", "CVE-2013-5589", "CVE-2014-2327", "CVE-2014-2328", "CVE-2014-2708", "CVE-2014-2709", "CVE-2014-4002", "CVE-2014-5025", "CVE-2014-5026", "CVE-2014-5261", "CVE-2014-5262", "CVE-2017-1000031", "CVE-2017-1000032");
  script_bugtraq_id(61657, 62001, 62005, 66392, 66387, 66555, 66630, 68257, 68759, 69213);

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cacti <= 0.8.8b Multiple Vulnerabilities (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("cacti_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("cacti/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Cacti is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Cacti is prone to multiple vulnerabilities:

  - Multiple SQL injection vulnerabilities in (1) api_poller.php and (2) utility.php allow remote attackers to execute arbitrary SQL commands via unspecified vectors. (CVE-2013-1434)

  - (1) snmp.php and (2) rrd.php allows remote attackers to execute arbitrary commands via shell metacharacters in unspecified vectors. (CVE-2013-1435)

  - Multiple cross-site scripting (XSS) vulnerabilities allow remote attackers to inject arbitrary web script or HTML via (1) the step parameter to install/index.php or (2) the id parameter to cacti/host.php. (CVE-2013-5588)

  - SQL injection vulnerability in cacti/host.php allows remote attackers to execute arbitrary SQL commands via the id parameter. (CVE-2013-5589)

  - Cross-site request forgery (CSRF) vulnerability allows remote attackers to hijack the authentication of users for unspecified commands, as demonstrated by requests that (1) modify binary files, (2) modify configurations, or (3) add arbitrary users. (CVE-2014-2327)

  - lib/graph_export.php allows remote authenticated users to execute arbitrary commands via shell metacharacters in unspecified vectors. (CVE-2014-2328)

  - SQL injection vulnerability in graph_xport.php allows remote attackers to execute arbitrary SQL commands via unspecified vectors. (CVE-2014-2708)

  - lib/rrd.php allows remote attackers to execute arbitrary commands via shell metacharacters in unspecified parameters. (CVE-2014-2709)

  - Multiple cross-site scripting (XSS) vulnerabilities allow remote attackers to inject arbitrary web script or HTML via the (1) drp_action parameter to cdef.php, (2) data_input.php, (3) data_queries.php, (4) data_sources.php, (5) data_templates.php, (6) graph_templates.php, (7) graphs.php, (8) host.php, or (9) host_templates.php or the (10) graph_template_input_id or (11) graph_template_id parameter to graph_templates_inputs.php. (CVE-2014-4002)

  - Cross-site scripting (XSS) vulnerability in data_sources.php allows remote authenticated users with console access to inject arbitrary web script or HTML via the name_cache parameter in a ds_edit action. (CVE-2014-5025)

  - Multiple cross-site scripting (XSS) vulnerabilities allow remote authenticated users with console access to inject arbitrary web script or HTML via a (1) Graph Tree Title in a delete or (2) edit action, (3) CDEF Name, (4) Data Input Method Name, or (5) Host Templates Name in a delete action, (6) Data Source Title, (7) Graph Title, or (8) Graph Template Name in a delete or (9) duplicate action. (CVE-2014-5026)

  - The graph settings script (graph_settings.php) allows remote attackers to execute arbitrary commands via shell metacharacters in a font size, related to the rrdtool commandline in lib/rrd.php. (CVE-2014-5261)

  - SQL injection vulnerability in the graph settings script (graph_settings.php) allows remote attackers to execute arbitrary SQL commands via unspecified vectors. (CVE-2014-5262)

  - SQL injection vulnerability in graph_templates_inputs.php allows remote attackers to execute arbitrary SQL commands via the graph_template_input_id and graph_template_id parameters. (CVE-2017-1000031)

  - Cross-Site scripting (XSS) vulnerabilities allow remote attackers to inject arbitrary web script or HTML via the parent_id parameter to tree.php and drp_action parameter to data_sources.php. (CVE-2017-1000032)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Cacti version 0.8.8b and prior.");

  script_tag(name:"solution", value:"Upgrade to version 0.8.8c or later.");

  script_xref(name:"URL", value:"http://bugs.cacti.net/view.php?id=2383");
  script_xref(name:"URL", value:"http://bugs.cacti.net/view.php?id=2405");
  script_xref(name:"URL", value:"http://bugs.cacti.net/view.php?id=2456");
  script_xref(name:"URL", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=742768");
  script_xref(name:"URL", value:"http://forums.cacti.net/viewtopic.php?f=21&t=50593");
  script_xref(name:"URL", value:"https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2016-007");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "0.8.8b")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.8.8c");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
