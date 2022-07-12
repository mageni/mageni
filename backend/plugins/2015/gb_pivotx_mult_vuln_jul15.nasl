###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pivotx_mult_vuln_jul15.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# PivotX Multiple Vulnerabilities - Jul15
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:pivotx:pivotx";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805938");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-5456", "CVE-2015-5457", "CVE-2015-5458");
  script_bugtraq_id(75577);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-07-27 14:22:08 +0530 (Mon, 27 Jul 2015)");
  script_name("PivotX Multiple Vulnerabilities - Jul15");

  script_tag(name:"summary", value:"The host is installed with PivotX and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  whether it is possible to read a cookie or not.");

  script_tag(name:"insight", value:"Multiple errors exists as the application

  - Does not validate input passed via the 'sess' parameter to 'fileupload.php'
    script.

  - Does not validate the new file extension when renaming a file with multiple
    extensions, like foo.php.php.

  - Does not validate input passed via the form method in modules/formclass.php
    script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to hijack web sessions, execute arbitrary code and create a specially
  crafted request that would execute arbitrary script code in a user's browser
  session within the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"PivotX version 2.3.10 and probably prior.");

  script_tag(name:"solution", value:"Upgrade PivotX to version 2.3.11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132474");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/535860/100/0/threaded");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pivotx_detect.nasl");
  script_mandatory_keys("PivotX/Installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://pivotx.net");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!pivPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:pivPort)){
  exit(0);
}

url = dir + '/index.php/"><script>alert(document.cookie)</script></scri' +
            'pt>?page=page&uid=3';

if(http_vuln_check(port:pivPort, url:url, check_header:TRUE,
  pattern:"<script>alert\(document.cookie\)</script>",
  extra_check:">PivotX"))
{
  report = report_vuln_url( port:pivPort, url:url );
  security_message(port:pivPort, data:report);
  exit(0);
}
