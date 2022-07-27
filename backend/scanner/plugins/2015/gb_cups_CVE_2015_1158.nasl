###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cups_CVE_2015_1158.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# CUPS < 2.0.3 Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:apple:cups";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105298");
  script_cve_id("CVE-2015-1158", "CVE-2015-1159");
  script_bugtraq_id(75098, 75106);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11872 $");

  script_name("CUPS < 2.0.3 Multiple Vulnerabilities");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/810572");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37336");

  script_tag(name:"impact", value:"CVE-2015-1158 may allow a remote unauthenticated
attacker access to privileged operations on the CUPS server. CVE-2015-1159 may allow
an attacker to execute arbitrary javascript in a user's browser.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
and check whether it is able to read cookie or not");

  script_tag(name:"insight", value:"CVE-2015-1158:
An issue with how localized strings are handled in cupsd allows a reference
counter to over-decrement when handling certain print job request errors. As a
result, an attacker can prematurely free an arbitrary string of global scope,
creating a dangling pointer to a repurposed block of memory on the heap. The
dangling pointer causes ACL verification to fail when parsing 'admin/conf' and
'admin' ACLs. The ACL handling failure results in unrestricted access to
privileged operations, allowing an unauthenticated remote user to upload a
replacement CUPS configuration file and mount further attacks.

CVE-2015-1159:
A cross-site scripting bug in the CUPS templating engine allows this bug to be
exploited when a user browses the web. In certain cases, the CGI template can
echo user input to file rather than escaping the text first. This may be used
to set up a reflected XSS attack in the QUERY parameter of the web interface
help page. By default, many linux distributions run with the web interface
activated, OS X has the web interface deactivated by default.");

  script_tag(name:"solution", value:"A patch addressing these issues has been
released for all supported versions of CUPS. For the version 2.0 branch (the latest
release), 2.0.3 contains the patch.");

  script_tag(name:"summary", value:"Various versions of CUPS are vulnerable
to a privilege escalation due to a memory management error.");

  script_tag(name:"affected", value:"CUPS < 2.0.3");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-06-15 15:24:12 +0200 (Mon, 15 Jun 2015)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("secpod_cups_detect.nasl");
  script_require_ports("Services/www", 631);
  script_mandatory_keys("CUPS/installed");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!cupsPort = get_app_port(cpe:CPE)){
  exit(0);
}

url = "/help/?QUERY=%3Ca%20href=%22%20%3E%3Cscript%3Ealert%28document.cooki" +
      "e%29%3C/script%3E%3C!--&SEARCH=Search";

if(http_vuln_check(port:cupsPort, url:url, pattern:"script>alert\(document.cookie\)</script>",
                   extra_check: make_list(">Online Help", "CUPS"), check_header:TRUE))
{
  report = report_vuln_url( port:cupsPort, url:url );
  security_message(port:cupsPort, data:report);
  exit(0);
}

exit(99);
