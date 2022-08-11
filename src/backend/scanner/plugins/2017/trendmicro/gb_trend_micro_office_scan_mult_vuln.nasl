###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trend_micro_office_scan_mult_vuln.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Trend Micro OfficeScan Multiple Vulnerabilities Oct17
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:trendmicro:officescan";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811870");
  script_version("$Revision: 11983 $");
  script_cve_id("CVE-2017-14083", "CVE-2017-14084", "CVE-2017-14085", "CVE-2017-14086",
                "CVE-2017-14087", "CVE-2017-14088", "CVE-2017-14089");
  script_bugtraq_id(101076);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-02 17:15:23 +0530 (Thu, 02 Nov 2017)");
  script_tag(name:"qod_type", value:"remote_active");
  script_name("Trend Micro OfficeScan Multiple Vulnerabilities Oct17");

  script_tag(name:"summary", value:"This host is running Trend Micro OfficeScan
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check if we are able to access the private key file or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An Unauthorized memory corruption error relate to 'cgiShowClientAdm.exe' file.

  - An improper access control mechanism on sensitive files.

  - Pre-authorization Start Remote Process errors in Micro OfficeScan.

  - Man-in-the-Middle (MitM) attack vulnerabilities.

  - An insufficient validation of user supplied input for 'Host Header'.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code and escalate privileges, obtain sensitive
  information and conduct spoofing attack.");

  script_tag(name:"affected", value:"Trend Micro OfficeScan 11.0 SP1 and XG (12.0).");

  script_tag(name:"solution", value:"Upgrade to Trend Micro OfficeScan
  11.0 SP1 CP 6426 or XG (12.0) CP 1708 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42895");
  script_xref(name:"URL", value:"https://success.trendmicro.com/solution/1118372");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_trend_micro_office_scan_detect_remote.nasl");
  script_mandatory_keys("TrendMicro/OfficeScan/Installed/Remote");
  script_require_ports("Services/www", 443, 4343);
  exit(0);
}


include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!trendPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:trendPort)) exit(0);

## Crafted url
url = dir + "/console/RemoteInstallCGI/cgiGetNTDomain.exe";

## Send crafted request and check for vulnerability
## NT Domain Disclosure confirmation
if (http_vuln_check(port: trendPort, url: url, pattern:'Content-Length:.*',
                    extra_check:make_list( '"NODES"', '"NAME"', '"ERROR_CODE"', '"RESPONSE"' ),
                    check_header: TRUE))
{
  report = report_vuln_url(port:trendPort, url:url);
  security_message(port:trendPort, data:report);
  exit(0);
}
