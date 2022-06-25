###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_egroupware_mult_vulns_09_10.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# EGroupware multiple vulnerabilities.
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

CPE = "cpe:/a:egroupware:egroupware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100824");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-09-24 14:46:08 +0200 (Fri, 24 Sep 2010)");
  script_cve_id("CVE-2010-3313", "CVE-2010-3314");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("EGroupware multiple vulnerabilities");

  script_xref(name:"URL", value:"http://www.egroupware.org/news?item=93");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_egroupware_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("egroupware/installed");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"EGroupware is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"1. Cross-site scripting (XSS) vulnerability in login.php in EGroupware
  1.4.001+.002, 1.6.001+.002 and possibly other versions before 1.6.003 and EPL 9.1 before 9.1.20100309 and
  9.2 before 9.2.20100309 allows remote attackers to inject arbitrary web script or HTML via the lang
  parameter.

  2. phpgwapi/js/fckeditor/editor/dialog/fck_spellerpages/spellerpages/serverscripts/spellchecker.php
  in EGroupware 1.4.001+.002, 1.6.001+.002 and possibly other versions before 1.6.003 and EPL 9.1 before 9.1.20100309
  and 9.2 before 9.2.20100309 allows remote attackers to execute arbitrary commands via shell metacharacters in the
  (1) aspell_path or (2) spellchecker_lang parameters.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);
url = string(dir,'/login.php?lang="%20style="width:100%;height:100%;display:block;position:absolute;top:0px;left:0px"%20onMouseOver="alert(%27vt-xss-test%27)');

if(http_vuln_check(port:port, url:url,pattern:"onMouseOver=.alert\('vt-xss-test')",check_header:TRUE)) {
  security_message(port:port);
  exit(0);
}

exit(0);