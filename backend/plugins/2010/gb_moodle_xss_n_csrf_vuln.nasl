##############################################################################
# OpenVAS Vulnerability Test
#
# Moodle Cross Site Scripting and Cross Site Request Forgery Vulnerabilities
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800798");
  script_version("2019-05-14T08:13:05+0000");
  script_tag(name:"last_modification", value:"2019-05-14 08:13:05 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-07-12 09:42:32 +0200 (Mon, 12 Jul 2010)");
  script_cve_id("CVE-2010-2229", "CVE-2010-2228",
                "CVE-2010-2231", "CVE-2010-2230");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Moodle Cross Site Scripting and Cross Site Request Forgery Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40248");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1530");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/06/21/2");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Moodle/Version");

  script_tag(name:"insight", value:"The flaws are due to,

  - Certain input passed to the 'MNET' access control interface is not properly
  sanitised before being used.

  - Improper validation of user supplied data to the 'blog/index.php' page,
  which allows remote attackers to inject arbitrary web script or HTML via
  unspecified parameters.

  - Error in 'KSES text cleaning filter' in 'lib/weblib.php' which fails to
  properly handle 'vbscript URIs', which allows remote authenticated users
  to conduct cross-site scripting (XSS) attacks via HTML input.

  - Allowing users to perform certain actions via 'HTTP requests' without
  performing any validity checks to verify the requests. This can be
  exploited to delete certain quiz reports by tricking a user into visiting
  a specially crafted site.");

  script_tag(name:"solution", value:"Upgrade to Moodle version 1.8.13 or 1.9.9 or later.");

  script_tag(name:"summary", value:"This host is running Moodle and is prone to Cross-Site Scripting
  and Cross Site Request Forgery Vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site
  and to gain knowledge of sensitive information or to conduct cross-site request forgery attacks.");

  script_tag(name:"affected", value:"Moodle version 1.8.x prior to 1.8.13

  Moodle version 1.9.x prior to 1.9.9");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

moodlePort = get_http_port(default:80);

moodleVer = get_version_from_kb(port:moodlePort, app:"moodle");
if(!moodleVer)
  exit(0);

if(version_in_range(version:moodleVer, test_version:"1.8", test_version2:"1.8.12") ||
   version_in_range(version:moodleVer, test_version:"1.9", test_version2:"1.9.8")){
  security_message(port:moodlePort);
  exit(0);
}

exit(0);