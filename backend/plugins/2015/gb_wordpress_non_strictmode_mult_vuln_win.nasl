###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_non_strictmode_mult_vuln_win.nasl 11975 2018-10-19 06:54:12Z cfischer $
#
# WordPress 'Non-Strict Mode' Multiple Cross-Site Scripting Vulnerabilities (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805987");
  script_version("$Revision: 11975 $");
  script_cve_id("CVE-2015-3438");
  script_bugtraq_id(74269);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:54:12 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-12 14:03:09 +0530 (Mon, 12 Oct 2015)");
  script_name("WordPress 'Non-Strict Mode' Multiple Cross-Site Scripting Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"This host is running WordPress and is prone
  to multiple cross site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to improper input
  data sanitization via four-byte UTF-8 character or via an invalid character.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session within
  the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"Wordpress versions before 4.1.2 on Windows.");

  script_tag(name:"solution", value:"Upgrade to version 4.1.2 or higher.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://wordpress.org/news/2015/04/wordpress-4-1-2");
  script_xref(name:"URL", value:"http://zoczus.blogspot.in/2015/04/plupload-same-origin-method-execution.html");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_windows");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wpPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!wpVer = get_app_version(cpe:CPE, port:wpPort)){
  exit(0);
}

if(version_is_less(version:wpVer, test_version:"4.1.2"))
{
  report = 'Installed Version: ' + wpVer + '\n' +
           'Fixed Version:     ' + "4.1.2" + '\n';

  security_message(data:report, port:wpPort);
  exit(0);
}
